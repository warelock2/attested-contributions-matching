# Attested Contributions Matching (Double-Blind)

A privacy-preserving system for verifying tax contributions using three Python CLI tools. This project allows citizens to prove their contribution status (e.g., Military or Libraries) to others without revealing their actual tax amounts, and without revealing their full status profile to matchers.

## Summary

The system uses a "Trust Triangle" between Citizens, the Government, and Peers:
1.  **Government Authority**: Sets contribution minimums and issues signed, blinded credentials (attestations).
2.  **Citizen Privacy**: Raw contribution amounts are only known to the citizen and the government.
3.  **Alignment-based Matching**: Peers match against each other's profiles based on alignment. 
    - **Default State**: A match is successful by default (Neutrality).
    - **Mismatch Detection**: The Matcher (Bob) can specify "make or break" categories. A match only succeeds if both parties share the **same status** (both Pass or both Fail) for every checked category.
    - **Double-Blind**: The Matcher hides which categories he is checking, and the Prover (Alice) hides her other statuses.
    - **Non-transferable**: The match result is session-specific and cannot be "leaked" to a third party.

## Cryptographic Protocols

| Protocol | Type | Usage in this Project |
| :--- | :--- | :--- |
| **Ed25519** | Asymmetric Signature | Government signs attestations to ensure authenticity and non-forgeability. |
| **Commutative XOR** | Blinding Protocol | Allows peers to match encrypted tokens without revealing policies or status labels. |
| **HMAC-SHA256** | Keyed Hashing | Government generates blinded reference tokens for each category-status pair. |
| **SHA-256** | Cryptographic Hash | Provides data integrity and serves as a building block for blinding operations. |
| **CSPRNG** | Randomness | Generates session-specific nonces to ensure match results are non-transferable. |

## File Manifest

### Source Scripts
- `issue_attestation.py`: The Government tool for initialization, policy setting, and attestation issuance.
- `submit_contribution.py`: The Citizen tool for declaring raw contribution values.
- `match_validator.py`: The Peer-to-Peer tool for performing double-blind alignment matches.
- `requirements.txt`: Python dependencies (`cryptography`).

### Generated Files (after workflow)
- `gov_manifest.json`: Public policy containing the Government's Public Key and category reference tokens.
- `gov_private.pem`: The Government's secret signing key.
- `gov_secret.bin`: The Government's master secret for generating blinded tokens.
- `contribution_<name>.json`: Raw citizen contribution data (Private to Citizen/Gov).
- `attestation_<name>.json`: Government-signed credential containing blinded status tokens.
- `blind_challenge_<A>_to_<B>.json`: A session-specific challenge file for a match.
- `blind_proof_<B>_to_<A>.json`: A session-specific proof file in response to a challenge.
- `match_secret_<A>_to_<B>.bin`: A local session key used by the matcher to verify the blind proof.

---

## Workflow Guide

### 1. Initialization (Government)

The government defines categories and minimum thresholds. This creates the public manifest everyone uses.

```bash
$ python3 issue_attestation.py --init "Military:1000,Libraries:500"
✔ Government initialized with 2 categories.
✔ Public manifest with reference tokens saved to gov_manifest.json

$ cat gov_manifest.json
{
    "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEATpsn8E4nOXhBZUeJlTEsby4rPzjg3PAVuSdo30ktyfY=\n-----END PUBLIC KEY-----\n",
    "categories": {
        "Military": 1000.0,
        "Libraries": 500.0
    },
    "reference_tokens": {
        "Military:True": "ae8011a3cfa01a749d6560acd5bc3954ac3ec03dddd77a1a454bb2655807b9c8",
        "Military:False": "8be789d610df7689d0663784edc9d747a13f01f4c7e7b51e5e06574c8b03010f",
        "Libraries:True": "8e59273c563032d847321ebf583f73315684705a61005a74e503f16962363162",
        "Libraries:False": "c2479d6e0030abd9ab08cdf8f9fe4308c53ed1084bf2473a433f49a39c751411"
    }
}
```

### 2. Contribution Submission (Citizen)

Alice and Bob declare their contributions.

```bash
$ python3 submit_contribution.py --name alice
# (e.g., Military: 1200 [PASS], Libraries: 100 [FAIL])

$ python3 submit_contribution.py --name bob
# (e.g., Military: 1100 [PASS], Libraries: 600 [PASS])
```

### 3. Attestation Issuance (Government)

The government issues credentials for both citizens.

```bash
$ python3 issue_attestation.py --process alice
✔ Attestation (v2.0) issued for alice

$ python3 issue_attestation.py --process bob
✔ Attestation (v2.0) issued for bob
```

### 4. Initiate Match (Matcher - Bob)

Bob matches with Alice. He chooses to check alignment on "Military". Since they both **PASSED**, they should match.

```bash
$ python3 match_validator.py --name bob --match alice --check "Military"
✔ Blind Challenge created: blind_challenge_bob_to_alice.json
Checking alignment on 1 categories.

$ cat blind_challenge_bob_to_alice.json
{
    "from": "bob",
    "to": "alice",
    "blinded_requirements": [
        "2b497c9bd65e9ddd9d53f08abfe2b3f56696228c5f862689928236deac67fe66"
    ],
    "nonce": "aae70fd035c6c7f7da185b7a10a991ff",
    "policy_type": "alignment"
}
```

### 5. Respond to Match (Prover - Alice)

Alice responds to the challenge.

```bash
$ python3 match_validator.py --name alice --respond blind_challenge_bob_to_alice.json
✔ Blind Proof created: blind_proof_alice_to_bob.json

$ cat blind_proof_alice_to_bob.json
{
    "nonce": "aae70fd035c6c7f7da185b7a10a991ff",
    "double_blinded_requirements": [
        "16a475a42cb2f64140736049d9780987f4a3a4aee918a9a5e4ba6de8bd52b2d8"
    ],
    "blinded_my_tokens": [
        "936d189c354c71e84045f06fb32683263e0b461f6b49f5363373e9534932f576",
        "ffaa9451fadcc04576285d3b9f64f97a570b572afd6cc816350712958d4058af"
    ],
    "original_attestation": { ... }
}
```

### 6. Verify Match (Matcher - Bob)

Bob verifies the proof.

```bash
$ python3 match_validator.py --name bob --verify blind_proof_alice_to_bob.json
✔ Government Signature Verified.

Alignment Analysis for alice:
 - Categories Aligned: 1 of 1

OVERALL RESULT: ✔ MATCH (All categories aligned)
```

**Note**: If Bob had checked "Libraries", the result would be `✖ NO MATCH` because Bob passed while Alice failed (a mismatch).

### 7. Optional: System Reset

Clear all generated keys, credentials, and session files.

```bash
$ python3 issue_attestation.py --reset
✔ System reset.
```
