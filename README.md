# Attested Contributions Matching (Double-Blind)

A privacy-preserving system for verifying tax contributions using three Python CLI tools. This project allows citizens to prove their contribution status (e.g., Military or Libraries) to others without revealing their actual tax amounts, and without revealing their full status profile to matchers.

## Summary

The system uses a "Trust Triangle" between Citizens, the Government, and Peers:
1.  **Government Authority**: Sets contribution minimums and issues signed, blinded credentials (attestations).
2.  **Citizen Privacy**: Raw contribution amounts are only known to the citizen and the government.
3.  **Identity-based Matching**: Peers match against each other's profiles based on **Exact Alignment**. 
    - **All-or-Nothing**: A match is only successful if the Challenger and Prover have the **identical status profile** across every category in the manifest.
    - **Profile Mirroring**: The tool only reveals a match if both parties have "mirrored" each other's contribution results (both Pass or both Fail for everything).
    - **Oracle Attack Protection**: If there is a mismatch, the tool provides **no diagnostic information** (it does not reveal which or how many categories mismatched). This prevents "scraping" or mapping out an individual's profile bit-by-bit.
    - **Double-Blind**: The Challenger's profile and the Prover's other statuses remain hidden from each other during the interactive exchange.
    - **Non-transferable**: The match result is session-specific and cannot be shared or leaked to third parties.

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
- `issue_attestation.py`: The Government tool for initialization and attestation issuance.
- `submit_contribution.py`: The Citizen tool for declaring raw contribution values.
- `match_validator.py`: The Peer-to-Peer tool for performing All-or-Nothing identity matches.
- `requirements.txt`: Python dependencies (`cryptography`).

### Generated Files (after workflow)
- `gov_manifest.json`: Public policy containing the Government's Public Key and category reference tokens.
- `gov_private.pem`: The Government's secret signing key.
- `gov_secret.bin`: The Government's master secret for generating blinded tokens.
- `contribution_<name>.json`: Raw citizen contribution data (Private to Citizen/Gov).
- `attestation_<name>.json`: Government-signed credential containing blinded status tokens.
- `identity_challenge_<A>_to_<B>.json`: A session-specific challenge for an identity match.
- `identity_proof_<B>_to_<A>.json`: A session-specific proof in response to a challenge.
- `match_secret_<A>_to_<B>.bin`: A local session key used by the matcher to verify the identity proof.

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
# (e.g., Military: 1100 [PASS], Libraries: 200 [FAIL])
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

Bob challenges Alice for an identity match. This implicitly checks **every** category in the manifest.

```bash
$ python3 match_validator.py --name bob --match alice
✔ Identity Challenge created: identity_challenge_bob_to_alice.json
Challenging alice for full profile alignment (2 categories).

$ cat identity_challenge_bob_to_alice.json
{
    "from": "bob",
    "to": "alice",
    "blinded_requirements": [
        "729116e718bea8df652152fc31bf9d531de3555d99db50663f8499357c4bdb3f",
        "4e0f4bb2d5cf9216a02aaa5a0f57dfd6b56956235f132db753149885823c3360"
    ],
    "nonce": "67e9bd73b65ce8be1d99c94a5c8d580f",
    "total_categories": 2
}
```

### 5. Respond to Match (Prover - Alice)

Alice responds to the identity challenge.

```bash
$ python3 match_validator.py --name alice --respond identity_challenge_bob_to_alice.json
✔ Identity Proof created: identity_proof_alice_to_bob.json

$ cat identity_proof_alice_to_bob.json
{
    "nonce": "67e9bd73b65ce8be1d99c94a5c8d580f",
    "double_blinded_requirements": [
        "2a7f7911be3232de58a9931baa1e8aa3401453484c1856fdcefff470756c2f8c",
        "16e12444734308179da26bbd94f6c826e89e50368ad02b2ca26ff5c08b1bc7d3"
    ],
    "blinded_my_tokens": [ ... ],
    "original_attestation": { ... },
    "total_categories": 2
}
```

### 6. Verify Match (Matcher - Bob)

Bob verifies the proof to see if Alice is his "Profile Mirror."

```bash
$ python3 match_validator.py --name bob --verify identity_proof_alice_to_bob.json
✔ Government Signature Verified.

Identity Analysis for alice:
 - Alignment: 2 / 2 categories matched.

OVERALL RESULT: ✔ IDENTITY MATCH (Profiles are identical)
```

**Note**: If even one category mismatched (e.g., if Alice passed Libraries and Bob failed it), the result would be `✖ NO MATCH (Profiles differ)` without revealing which category failed.

### 7. Optional: System Reset

Clear all generated keys, credentials, and session files.

```bash
$ python3 issue_attestation.py --reset
✔ System reset.
```
