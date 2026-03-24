import argparse
import json
import os
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

MANIFEST_FILE = "gov_manifest.json"

def blind_token(token_input, secret_key):
    """Blinds a token using a session secret (truly commutative XOR)."""
    if isinstance(token_input, str):
        try:
            token_bytes = bytes.fromhex(token_input)
        except ValueError:
            token_bytes = hashlib.sha256(token_input.encode('utf-8')).digest()
    else:
        token_bytes = token_input

    key_h = hashlib.sha256(secret_key.encode('utf-8')).digest()
    blinded = bytes(a ^ b for a, b in zip(token_bytes, key_h))
    return blinded.hex()

def create_blind_challenge(target_citizen, check_categories, my_name):
    """
    Bob initiates a challenge based on alignment.
    He checks his own attestation for the status of the categories he cares about.
    """
    if not os.path.exists(MANIFEST_FILE):
        print("Error: Public manifest not found.")
        return

    my_attestation_file = f"attestation_{my_name}.json"
    if not os.path.exists(my_attestation_file):
        print(f"Error: Your own attestation {my_attestation_file} not found. You need an attestation to perform a check.")
        return

    with open(MANIFEST_FILE, "r") as f:
        manifest = json.load(f)
    with open(my_attestation_file, "r") as f:
        my_attestation = json.load(f)

    my_secret = secrets.token_hex(32)
    with open(f"match_secret_{my_name}_to_{target_citizen}.bin", "w") as f:
        f.write(my_secret)

    # Bob finds the tokens that represent HIS OWN status for the categories he wants to check
    blinded_requirements = []
    
    if check_categories:
        categories_to_check = [c.strip() for c in check_categories.split(',')]
        for cat in categories_to_check:
            # We need to find which token (True or False) Bob has for this category
            # We look at the manifest reference tokens and see which one is in Bob's earned_tokens
            found = False
            for status in ["True", "False"]:
                ref_token = manifest['reference_tokens'].get(f"{cat}:{status}")
                if ref_token in my_attestation['payload']['earned_tokens']:
                    blinded_requirements.append(blind_token(ref_token, my_secret))
                    found = True
                    break
            if not found:
                print(f"Warning: Category '{cat}' not found in your attestation or manifest.")

    challenge = {
        "from": my_name,
        "to": target_citizen,
        "blinded_requirements": blinded_requirements,
        "nonce": secrets.token_hex(16),
        "policy_type": "alignment"
    }

    filename = f"blind_challenge_{my_name}_to_{target_citizen}.json"
    with open(filename, "w") as f:
        json.dump(challenge, f, indent=4)
    print(f"✔ Blind Challenge created: {filename}")
    if not blinded_requirements:
        print("Note: No categories specified. Match will succeed by default if signature is valid.")
    else:
        print(f"Checking alignment on {len(blinded_requirements)} categories.")

def respond_to_blind_challenge(challenge_file, my_name):
    """Alice blinds Bob's requirements and her own tokens."""
    if not os.path.exists(challenge_file):
        print(f"Error: Challenge file {challenge_file} not found.")
        return
    if not os.path.exists(f"attestation_{my_name}.json"):
        print(f"Error: Your attestation attestation_{my_name}.json not found.")
        return

    with open(challenge_file, "r") as f:
        challenge = json.load(f)
    with open(f"attestation_{my_name}.json", "r") as f:
        attestation = json.load(f)

    my_secret = secrets.token_hex(32)

    double_blinded_requirements = [blind_token(br, my_secret) for br in challenge['blinded_requirements']]
    blinded_my_tokens = [blind_token(t, my_secret) for t in attestation['payload']['earned_tokens']]

    proof = {
        "nonce": challenge['nonce'],
        "double_blinded_requirements": double_blinded_requirements,
        "blinded_my_tokens": blinded_my_tokens,
        "original_attestation": attestation
    }

    output_file = f"blind_proof_{my_name}_to_{challenge['from']}.json"
    with open(output_file, "w") as f:
        json.dump(proof, f, indent=4)
    print(f"✔ Blind Proof created: {output_file}")

def verify_blind_proof(proof_file, my_name):
    """Bob verifies alignment."""
    if not os.path.exists(proof_file):
        print(f"Error: Proof file {proof_file} not found.")
        return

    with open(proof_file, "r") as f:
        proof = json.load(f)
    
    peer_name = proof['original_attestation']['payload']['citizen']
    secret_file = f"match_secret_{my_name}_to_{peer_name}.bin"
    if not os.path.exists(secret_file):
        print("Error: Session secret not found.")
        return
    with open(secret_file, "r") as f:
        my_secret = f.read()

    # Verify Signature
    with open(MANIFEST_FILE, "r") as f:
        manifest = json.load(f)
    public_key = serialization.load_pem_public_key(manifest['public_key'].encode('utf-8'))
    payload_bytes = json.dumps(proof['original_attestation']['payload'], sort_keys=True).encode('utf-8')
    signature_bytes = bytes.fromhex(proof['original_attestation']['signature'])
    
    try:
        public_key.verify(signature_bytes, payload_bytes)
        print("✔ Government Signature Verified.")
    except:
        print("✖ Invalid Gov Signature!")
        return

    # Alignment Check
    alice_tokens_double_blinded = [blind_token(t, my_secret) for t in proof['blinded_my_tokens']]
    
    matches = 0
    total_requirements = len(proof['double_blinded_requirements'])
    
    for req in proof['double_blinded_requirements']:
        if req in alice_tokens_double_blinded:
            matches += 1

    print(f"\nAlignment Analysis for {peer_name}:")
    if total_requirements > 0:
        print(f" - Categories Aligned: {matches} of {total_requirements}")
        if matches == total_requirements:
            print("\nOVERALL RESULT: ✔ MATCH (All categories aligned)")
        else:
            print("\nOVERALL RESULT: ✖ NO MATCH (Mismatch detected)")
    else:
        print(" - No specific categories were checked.")
        print("\nOVERALL RESULT: ✔ MATCH (Default)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Alignment-based Double-Blind Matcher")
    parser.add_argument("--match", type=str, help="Citizen to match with")
    parser.add_argument("--check", type=str, help="Categories to check for alignment (e.g. 'Military,Libraries')")
    parser.add_argument("--name", type=str, help="Your name")
    parser.add_argument("--respond", type=str, help="Challenge file to respond to")
    parser.add_argument("--verify", type=str, help="Proof file to verify")
    
    args = parser.parse_args()
    if args.match and args.name:
        create_blind_challenge(args.match, args.check, args.name)
    elif args.respond and args.name:
        respond_to_blind_challenge(args.respond, args.name)
    elif args.verify and args.name:
        verify_blind_proof(args.verify, args.name)
    else:
        parser.print_help()
