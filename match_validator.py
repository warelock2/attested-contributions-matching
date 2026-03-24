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

def create_identity_challenge(target_citizen, my_name):
    """
    Bob initiates an All-or-Nothing Identity Challenge.
    He includes his blinded status tokens for EVERY category in the manifest.
    """
    if not os.path.exists(MANIFEST_FILE):
        print("Error: Public manifest not found.")
        return

    my_attestation_file = f"attestation_{my_name}.json"
    if not os.path.exists(my_attestation_file):
        print(f"Error: Your own attestation {my_attestation_file} not found.")
        return

    with open(MANIFEST_FILE, "r") as f:
        manifest = json.load(f)
    with open(my_attestation_file, "r") as f:
        my_attestation = json.load(f)

    my_secret = secrets.token_hex(32)
    with open(f"match_secret_{my_name}_to_{target_citizen}.bin", "w") as f:
        f.write(my_secret)

    # Bob MUST include his status token for EVERY category defined in the manifest
    blinded_requirements = []
    all_categories = manifest['categories'].keys()
    
    for cat in all_categories:
        found = False
        for status in ["True", "False"]:
            ref_token = manifest['reference_tokens'].get(f"{cat}:{status}")
            if ref_token in my_attestation['payload']['earned_tokens']:
                blinded_requirements.append(blind_token(ref_token, my_secret))
                found = True
                break
        if not found:
            print(f"Error: Category '{cat}' from manifest not found in your attestation!")
            return

    challenge = {
        "from": my_name,
        "to": target_citizen,
        "blinded_requirements": blinded_requirements,
        "nonce": secrets.token_hex(16),
        "total_categories": len(all_categories)
    }

    filename = f"identity_challenge_{my_name}_to_{target_citizen}.json"
    with open(filename, "w") as f:
        json.dump(challenge, f, indent=4)
    print(f"✔ Identity Challenge created: {filename}")
    print(f"Challenging {target_citizen} for full profile alignment ({len(all_categories)} categories).")

def respond_to_identity_challenge(challenge_file, my_name):
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

    # Alice double-blinds Bob's requirements
    double_blinded_requirements = [blind_token(br, my_secret) for br in challenge['blinded_requirements']]
    # Alice blinds ALL her own earned tokens
    blinded_my_tokens = [blind_token(t, my_secret) for t in attestation['payload']['earned_tokens']]

    proof = {
        "nonce": challenge['nonce'],
        "double_blinded_requirements": double_blinded_requirements,
        "blinded_my_tokens": blinded_my_tokens,
        "original_attestation": attestation,
        "total_categories": challenge['total_categories']
    }

    output_file = f"identity_proof_{my_name}_to_{challenge['from']}.json"
    with open(output_file, "w") as f:
        json.dump(proof, f, indent=4)
    print(f"✔ Identity Proof created: {output_file}")

def verify_identity_proof(proof_file, my_name):
    """Bob verifies if Alice's profile is an EXACT MATCH for his own."""
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

    # 1. Verify Government Signature
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

    # 2. Identity Match Logic (All-or-Nothing)
    # Bob applies his secret to Alice's blinded tokens
    alice_tokens_double_blinded = [blind_token(t, my_secret) for t in proof['blinded_my_tokens']]
    
    matches = 0
    total_expected = proof['total_categories']
    
    # We check how many of Bob's double-blinded requirements exist in Alice's set
    for req in proof['double_blinded_requirements']:
        if req in alice_tokens_double_blinded:
            matches += 1

    print(f"\nIdentity Analysis for {peer_name}:")
    
    # ALL-OR-NOTHING: We only reveal if it is a PERFECT match
    if matches == total_expected:
        print(f" - Alignment: {matches} / {total_expected} categories matched.")
        print("\nOVERALL RESULT: ✔ IDENTITY MATCH (Profiles are identical)")
    else:
        # We do NOT reveal how many matched, to prevent bit-scraping
        print(" - Alignment: MISMATCH detected.")
        print("\nOVERALL RESULT: ✖ NO MATCH (Profiles differ)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="All-or-Nothing Identity Matcher")
    parser.add_argument("--match", type=str, help="Citizen to challenge for identity match")
    parser.add_argument("--name", type=str, help="Your name")
    parser.add_argument("--respond", type=str, help="Identity challenge file to respond to")
    parser.add_argument("--verify", type=str, help="Identity proof file to verify")
    
    args = parser.parse_args()
    if args.match and args.name:
        create_identity_challenge(args.match, args.name)
    elif args.respond and args.name:
        respond_to_identity_challenge(args.respond, args.name)
    elif args.verify and args.name:
        verify_identity_proof(args.verify, args.name)
    else:
        parser.print_help()
