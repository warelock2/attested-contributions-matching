import argparse
import json
import os
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

MANIFEST_FILE = "gov_manifest.json"
PRIVATE_KEY_FILE = "gov_private.pem"
MASTER_SECRET_FILE = "gov_secret.bin"

def generate_token(master_secret, category, status):
    """Generates a unique token for a category-status pair."""
    msg = f"{category}:{status}".encode('utf-8')
    return hmac.new(master_secret, msg, hashlib.sha256).hexdigest()

def init_government(categories_str):
    """Initializes keys, master secret, and manifest with reference tokens."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    master_secret = secrets.token_bytes(32)

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(MASTER_SECRET_FILE, "wb") as f:
        f.write(master_secret)

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    categories = {}
    reference_tokens = {}
    for item in categories_str.split(','):
        name, min_val = item.split(':')
        name = name.strip()
        categories[name] = float(min_val.strip())
        # Pre-generate reference tokens for both True and False
        reference_tokens[f"{name}:True"] = generate_token(master_secret, name, True)
        reference_tokens[f"{name}:False"] = generate_token(master_secret, name, False)

    manifest = {
        "public_key": public_key_bytes,
        "categories": categories,
        "reference_tokens": reference_tokens
    }

    with open(MANIFEST_FILE, "w") as f:
        json.dump(manifest, f, indent=4)

    print(f"✔ Government initialized with {len(categories)} categories.")
    print(f"✔ Public manifest with reference tokens saved to {MANIFEST_FILE}")

def process_attestation(citizen_name):
    """Issues attestation containing the specific tokens earned by the citizen."""
    if not os.path.exists(MANIFEST_FILE) or not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(MASTER_SECRET_FILE):
        print("Error: Government not initialized.")
        return

    contribution_file = f"contribution_{citizen_name}.json"
    if not os.path.exists(contribution_file):
        print(f"Error: {contribution_file} not found.")
        return

    with open(MANIFEST_FILE, "r") as f:
        manifest = json.load(f)
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(MASTER_SECRET_FILE, "rb") as f:
        master_secret = f.read()
    with open(contribution_file, "r") as f:
        contribution = json.load(f)

    # Calculate pass/fail and collect the corresponding tokens
    earned_tokens = []
    for cat, min_val in manifest['categories'].items():
        status = contribution.get('contributions', {}).get(cat, 0) >= min_val
        token = generate_token(master_secret, cat, status)
        earned_tokens.append(token)

    payload = {
        "citizen": citizen_name,
        "earned_tokens": earned_tokens,
        "version": "2.0"
    }
    payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
    signature = private_key.sign(payload_bytes)

    attestation = {
        "payload": payload,
        "signature": signature.hex()
    }
    
    with open(f"attestation_{citizen_name}.json", "w") as f:
        json.dump(attestation, f, indent=4)

    print(f"✔ Attestation (v2.0) issued for {citizen_name}")

def reset_system():
    files_to_delete = [f for f in os.listdir(".") if f.endswith(".json") or f.endswith(".pem") or f.endswith(".bin")]
    for f in files_to_delete:
        os.remove(f)
    print("✔ System reset.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Government Attestation Issuer")
    parser.add_argument("--init", type=str, help="Initialize with categories")
    parser.add_argument("--process", type=str, help="Process citizen attestation")
    parser.add_argument("--reset", action="store_true", help="Reset system")
    args = parser.parse_args()
    if args.init: init_government(args.init)
    elif args.process: process_attestation(args.process)
    elif args.reset: reset_system()
    else: parser.print_help()
