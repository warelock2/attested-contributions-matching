# Attested Contributions Matching (Double-Blind)

A privacy-preserving system for verifying tax contributions using three Python CLI tools. This project allows citizens to prove their contribution status (e.g., Military or Libraries) to others without revealing their actual tax amounts, and without revealing their full status profile to matchers.

## Summary

The system uses a "Trust Triangle" between Citizens, the Government, and Peers:
1.  **Government Authority**: Sets contribution minimums and issues signed credentials (attestations) containing secret status tokens.
2.  **Citizen Privacy**: Raw contribution amounts are only known to the citizen and the government.
3.  **Identity-based Matching**: Peers match against each other's profiles based on **Exact Alignment**. 
    - **All-or-Nothing**: A match is only successful if the Challenger and Prover have the **identical status profile** across every category.
    - **Profile Mirroring**: A citizen can only challenge another citizen on statuses they themselves possess. If Bob failed "Military", he does not have the "Military: Pass" token, so he cannot ask Alice if she passed.
    - **Oracle Attack Protection**: The public manifest does NOT contain reference tokens. There is no "dictionary" to decode a citizen's status.
    - **Double-Blind**: The Challenger's profile and the Prover's other statuses remain hidden from each other during the interactive exchange.
    - **Non-transferable**: The match result is session-specific and cannot be shared or leaked to third parties.

## Cryptographic Protocols

We use "Private Set Intersection (PSI) based on Commutative Blinding" or just "Commutative PSI", rather than needing full-blown "Zero Knowledge Proofs" or "ZKP" to achieve the project's goals.

| Protocol | Type | Usage in this Project |
| :--- | :--- | :--- |
| **Ed25519** | Asymmetric Signature | Government signs attestations to ensure authenticity and non-forgeability. |
| **Commutative XOR** | Blinding Protocol | Allows peers to match encrypted tokens without revealing policies or status labels. |
| **HMAC-SHA256** | Keyed Hashing | Government generates **Secret Universal Tokens** for each category-status pair. |
| **SHA-256** | Cryptographic Hash | Provides data integrity and serves as a building block for blinding operations. |
| **CSPRNG** | Randomness | Generates session-specific nonces to ensure match results are non-transferable. |

## File Manifest

### Source Scripts
- `issue_attestation.py`: The Government tool for initialization and attestation issuance.
- `submit_contribution.py`: The Citizen tool for declaring raw contribution values.
- `match_validator.py`: The Peer-to-Peer tool for performing All-or-Nothing identity matches.
- `requirements.txt`: Python dependencies (`cryptography`).

### Generated Files (after workflow)
- `gov_manifest.json`: Public policy containing the Government's Public Key and category thresholds. **(No longer contains reference tokens)**
- `gov_private.pem`: The Government's secret signing key.
- `gov_secret.bin`: The Government's master secret for generating blinded tokens.
- `contribution_<name>.json`: Raw citizen contribution data (Private to Citizen/Gov).
- `attestation_<name>.json`: Government-signed credential containing secret status tokens.
- `identity_challenge_<A>_to_<B>.json`: A session-specific challenge for an identity match.
- `identity_proof_<B>_to_<A>.json`: A session-specific proof in response to a challenge. **(Does NOT contain raw tokens)**
- `match_secret_<A>_to_<B>.bin`: A local session key used by the matcher to verify the identity proof.

---

## Workflow Guide

### 1. Initialization (Government)

The government defines categories and minimum thresholds. This creates the public manifest.

**Cryptography**: 
- **Ed25519 Key Generation**: Creates a root of trust for signing future credentials.
- **HMAC Master Secret**: A single secret key is generated to derive all future status tokens. This ensures only G can create valid tokens.

```bash
$ python3 issue_attestation.py --init "Military:1000,Libraries:500"
✔ Government initialized with 2 categories.
✔ Public manifest saved to gov_manifest.json
```

### 2. Contribution Submission (Citizen)

Alice and Bob declare their contributions.

**Intent**: Private data collection.
- **Mitigation**: Data is stored locally in `contribution_<name>.json` and is never transmitted over the network in this prototype (representing a direct secure channel to G).

```bash
$ python3 submit_contribution.py --name alice
# (e.g., Military: 1200 [PASS], Libraries: 100 [FAIL])

$ python3 submit_contribution.py --name bob
# (e.g., Military: 1100 [PASS], Libraries: 200 [FAIL])
```

### 3. Attestation Issuance (Government)

The government issues credentials for both citizens.

**Cryptography**:
- **HMAC-SHA256**: Generates **Universal Secret Tokens** based on the citizen's status (Pass/Fail). These tokens are deterministic but secret; G does not need to store them, but can always regenerate them.
- **Ed25519 Signature**: G signs the list of tokens. This prevents Alice from modifying her tokens (e.g., swapping a Fail for a Pass) because she cannot forge G's signature.

```bash
$ python3 issue_attestation.py --process alice
✔ Attestation (v2.0) issued for alice
```

### 4. Initiate Match (Matcher - Bob)

Bob challenges Alice for an identity match. Bob uses his own tokens to build the challenge.

**Cryptography**:
- **Blinding (XOR + One-Time Pad)**: Bob XORs his secret tokens with a random session key (`match_secret`).
- **Mitigation**: This "blinds" the tokens. Alice receives only random noise. She cannot reverse-engineer Bob's tokens to see his status. She can only match against them if she *already* holds the identical token.

```bash
$ python3 match_validator.py --name bob --match alice
✔ Identity Challenge created: identity_challenge_bob_to_alice.json
Challenging alice for full profile alignment (2 categories).
```

### 5. Respond to Match (Prover - Alice)

Alice responds to the identity challenge. She sends blinded tokens and the government signature, but **omits** her raw tokens.

**Cryptography**:
- **Double-Blinding**: Alice adds her own blinding layer to Bob's requirements and blinds her own tokens.
- **Privacy-Locked Proof**: By stripping the cleartext tokens and only sending the blinded math + signature, Alice ensures that **only Bob** (who holds the session secret) can verify the match.
- **Mitigation**: Prevents "Transferability." If Bob sends this proof to Charlie, Charlie sees only random hex strings and cannot verify anything.

```bash
$ python3 match_validator.py --name alice --respond identity_challenge_bob_to_alice.json
✔ Identity Proof created: identity_proof_alice_to_bob.json
```

### 6. Verify Match (Matcher - Bob)

Bob verifies the proof. If the blinded tokens match perfectly, he reconstructs Alice's profile using his own tokens and verifies the Government's signature.

**Cryptography**:
- **Reconstruction Verification**: Bob un-blinds the result. If (and only if) the tokens match, he swaps in his own valid tokens to reconstruct the original payload G signed.
- **Ed25519 Verification**: Bob verifies G's signature on this reconstructed payload.
- **Mitigation**: This ensures Alice didn't just send random garbage that "happened" to XOR correctly. She must possess a valid signature from G on the exact tokens Bob has.

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

---

## Cryptographic Secrets Handling Analysis

### Cryptographic Secrets & Artifacts Table

| Artifact | Who Knows It | Who *Should* Know It | Who Can Lie (and how) | Who Can't Lie (and why) |
| :--- | :--- | :--- | :--- | :--- |
| **`gov_private.pem`**<br>(Ed25519 Private Key) | **G** | **G** | **G**: N/A (Root of Trust). | **A, B, C**: Cannot forge signatures. |
| **`gov_secret.bin`**<br>(HMAC Master Secret) | **G** | **G** | **G**: N/A (Root of Trust). | **A, B, C**: Cannot generate valid status tokens. |
| **`gov_manifest.json`**<br>(Public Key & Thresholds) | **Public** | **Public** | **G**: N/A (Root of Trust). | **A, B, C**: Cannot alter the policy. |
| **`contribution_X.json`**<br>(Raw Contribution Data) | **X**, **G** | **X**, **G** | **X**: N/A (G verifies funds). | **G**: Cannot modify submission. |
| **`attestation_X.json`**<br>(Signed Secret Tokens) | **X**, **G** | **X**, **G** | **G**: N/A (Root of Trust). | **X**: Cannot modify tokens (Signed). |
| **`match_secret_B_to_A.bin`**<br>(Bob's Session Key) | **B** | **B** | **B**: N/A (Self-Interest). | **A**: Cannot derive key. |
| **`identity_challenge_B_to_A.json`**<br>(Blinded Requirements) | **B**, **A** | **B**, **A** | **B**: N/A (Self-Interest). | **B**: Cannot fake a status he doesn't have. |
| **`identity_proof_A_to_B.json`**<br>(Double-Blinded Tokens) | **A**, **B** | **A**, **B** | **A**: N/A (Self-Interest). | **A**: Cannot fake a "Pass" status (Signature check). |

## Conclusion

This system design aligns with the principles of voluntaryism and spontaneous order, effectively replacing the centralized enforcement of taxation with a decentralized, reputation-based social mechanism.
   
  1. Shift from Coercion to Social Accountability
  By moving the enforcement mechanism from a central authority (jail/fines for non-payment) to the edges of the network (social
  ostracization or acceptance), you create a marketplace for governance.
   * Voluntary Funding: Projects live or die based on their actual perceived value to the citizenry, not on the ability of a
     politician to bundle them into an omnibus bill.
   * Social Filtering: "Birds of a feather" finding each other creates micro-communities of shared values. A pacifist community can
     strictly enforce non-funding of the military within their social circles, while a nationalist community can do the opposite.
   
  2. The "All-or-Nothing" Dynamic
  Treating all projects with "equal importance" in the match creates a very high bar for social cohesion.
   * Feature: It prevents "cafeteria-style" citizenship where people cherry-pick easy virtues. To match with someone, you must
     align on every dimension the society (or at least the government manifest) deems relevant.
   * Bug/Feature: It might lead to extreme fragmentation. If the government defines 50 categories, the probability of finding a
     perfect match drops exponentially, potentially isolating everyone. This effectively pressures the government to keep the list
     of categories small and broadly distinct (e.g., just "Defense", "Infrastructure", "Welfare") rather than granular.
   
  3. Asymmetry of Information
   * Challenger Advantage: B learns A's status (pass/fail) relative to B, but A learns nothing about B during that
     specific handshake.
   * Mutuality: This encourages a "tit-for-tat" protocol where social norms would likely dictate a mutual exchange: "I'll prove to
     you if you prove to me."

  4. Privacy as an Enabler
  Crucially, the Zero-Knowledge / Double-Blind nature of this code is what makes this feasible. Without it, people would be
  terrified to reveal their political/financial choices for fear of broad persecution.
   * Because the proof is non-transferable (mathematically bound to the session), B cannot prove to C that A failed. B can only
     spread a rumor. This protects A from systemic cancellation while still allowing B to exercise their freedom of association.

  Conclusion
  This system models Libertarian Panarchism implemented via cryptography. It allows for the emergence of distinct, voluntary
  communities co-existing within the same physical territory, defined not by borders but by their cryptographic
  handshake. It maximizes individual liberty by making funding voluntary, but preserves community cohesion by allowing individuals
  to filter their interactions based on those funding choices.
