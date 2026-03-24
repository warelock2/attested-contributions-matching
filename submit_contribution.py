import argparse
import json
import os

MANIFEST_FILE = "gov_manifest.json"

def submit_contribution(name):
    """Prompts for contributions and saves them to a JSON file."""
    if not os.path.exists(MANIFEST_FILE):
        print("Error: Public manifest not found. Has the government initialized yet?")
        return

    with open(MANIFEST_FILE, "r") as f:
        manifest = json.load(f)

    print(f"--- Contribution Submission for {name} ---")
    print("Required Categories and Minimums:")
    for cat, min_val in manifest['categories'].items():
        print(f" - {cat}: {min_val}")
    print("-" * 40)

    contributions = {}
    for cat in manifest['categories']:
        while True:
            try:
                val = float(input(f"Enter contribution for {cat}: "))
                contributions[cat] = val
                break
            except ValueError:
                print("Invalid input. Please enter a number.")

    data = {
        "citizen": name,
        "contributions": contributions
    }

    output_file = f"contribution_{name}.json"
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)

    print(f"\n✔ Contributions saved to {output_file}")
    print("You can now share this with the government for attestation.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Citizen Contribution Submitter")
    parser.add_argument("--name", type=str, required=True, help="Your name/identifier")

    args = parser.parse_args()
    submit_contribution(args.name)
