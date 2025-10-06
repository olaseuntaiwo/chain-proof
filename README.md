# 📜 ChainProof — Bitcoin-Backed Decentralized Notarization Protocol

ChainProof is a decentralized notarization system that anchors cryptographic proofs of digital document existence to Bitcoin via the Stacks blockchain. It offers **tamper-proof timestamps**, **zero-knowledge verification**, and **permanent attestation** without compromising document confidentiality.

By leveraging Bitcoin's immutability and Stacks’ smart contract layer, ChainProof delivers a decentralized alternative to traditional notaries—free of intermediaries, recurring costs, and centralized points of failure.

---

## 🚀 Key Features

* **Bitcoin Finality:** All attestations are anchored on Bitcoin’s ledger via Stacks, inheriting its security model.
* **Zero-Knowledge Proofs:** Verifies authenticity without revealing the original document.
* **Privacy-Preserving:** Only SHA-256 hashes are stored on-chain.
* **Immutable Records:** Once written, attestations are permanent and censorship-resistant.
* **Self-Service Verification:** Anyone can verify a document independently using just its hash.
* **No Expiration:** Attestations never expire and require no renewal.

---

## 📐 System Overview

### High-Level Architecture

```plaintext
User → [Hash Document Locally]
     → [Submit Attestation to ChainProof (Stacks Contract)]
        → [Record Hash + Metadata On-Chain]
           → [Bitcoin Finality via Stacks Anchor]
```

* **Users** locally compute a SHA-256 hash of any digital content (contracts, IP, disclosures).
* The **ChainProof smart contract** immutably records this hash alongside metadata (originator, recipient, block height).
* **Verification** is possible by submitting the same hash; the contract confirms if a matching attestation exists.

---

## 📘 Contract Architecture

### Core Modules

| Component                    | Type       | Purpose                                                 |
| ---------------------------- | ---------- | ------------------------------------------------------- |
| `attestations`               | `map`      | Stores immutable records of attestations                |
| `hash-verification-registry` | `map`      | Allows reverse lookups and tracks verification attempts |
| `user-attestation-count`     | `map`      | Tracks attestation activity per user                    |
| `total-attestations`         | `data-var` | Global counter for total attestations                   |
| `protocol-version`           | `data-var` | Manages semantic versioning of the contract             |

### Key Public Functions

| Function                     | Purpose                                                                   |
| ---------------------------- | ------------------------------------------------------------------------- |
| `create-attestation`         | Anchors a SHA-256 hash as an immutable proof between sender and recipient |
| `verify-attestation`         | Performs privacy-preserving verification using only the document hash     |
| `update-protocol-version`    | Allows owner to upgrade protocol version (non-downgradable)               |
| `get-attestation-info`       | Retrieves full metadata for a given attestation                           |
| `hash-exists`                | Checks if a given hash has already been notarized                         |
| `get-verification-attempts`  | Returns number of times a given hash has been verified                    |
| `get-user-attestation-count` | Returns number of attestations submitted by a specific user               |
| `get-total-attestations`     | Returns the total number of attestations created system-wide              |

### Access Control

* **Owner-only** operations (e.g., `update-protocol-version`) are restricted using the `CONTRACT_OWNER` constant.
* Self-attestation is prohibited to preserve non-repudiation.

---

## 🔄 Data Flow

### Attestation Lifecycle

1. **Hashing (off-chain):** User computes a 32-byte SHA-256 hash of a document.
2. **Submission (on-chain):** `create-attestation` records:

   * Originator and recipient
   * Content hash
   * Block height (used as timestamp)
3. **Verification:** Any user can call `verify-attestation` with a hash. On match:

   * Verification status is marked `true`
   * Verification count is incremented

---

## 🛡 Use Cases

* **Intellectual Property (IP):** Prove patent or copyright priority
* **Legal & Regulatory:** Timestamp contracts, compliance documents, audit logs
* **Whistleblower Protection:** Prove document existence without revealing content
* **Digital Evidence:** Provide chain-of-custody anchored to Bitcoin

---

## ✅ Deployment & Compatibility

* **Stacks Version:** Compatible with Clarity v1 (Stacks 2.x)
* **Protocol Versioning:** Managed through `protocol-version` for future upgrades
* **Contract Owner:** Initial owner is `tx-sender` at deployment; used for governance only

---

## 🧪 Example Usage

```lisp
;; Create an attestation
(create-attestation 'SP2ABC123... (sha256 "contract.pdf"))

;; Verify using the same hash
(verify-attestation u1 (sha256 "contract.pdf"))

;; Check if a hash exists
(hash-exists (sha256 "contract.pdf"))

;; Get attestation metadata
(get-attestation-info u1)
```

---

## 🔐 Security & Privacy

* Only content hashes are stored; raw data is never on-chain.
* Verification is deterministic and transparent.
* All operations are bound by input validation and permission checks.
* Designed to comply with digital evidence standards (e.g., audit trails, immutability).

---

## 📄 License

MIT License. See [`LICENSE`](./LICENSE) for details.
