;; Title: ChainProof
;;
;; Summary:
;; ChainProof is a decentralized notarization protocol that transforms Bitcoin
;; into a permanent timestamping authority. By anchoring cryptographic hashes
;; through Stacks' settlement layer, it creates immutable proofs of document
;; existence without exposing confidential content-enabling trustless verification
;; for intellectual property, legal contracts, and compliance records.
;;
;; Description:
;; ChainProof establishes a global attestation infrastructure where any digital
;; asset can receive a tamper-proof timestamp backed by Bitcoin's security model.
;; The protocol operates on zero-knowledge principles: only SHA-256 hashes are
;; stored on-chain, ensuring complete content privacy while maintaining
;; cryptographic verifiability. Each attestation creates an immutable record
;; linking originators to recipients at a specific block height, establishing
;; provable chains of custody that withstand legal scrutiny. Unlike centralized
;; notaries, ChainProof eliminates intermediaries, recurring fees, and expiration
;; dates-attestations exist permanently on Bitcoin's immutable ledger. The system
;; excels in scenarios requiring both privacy and proof: patent priority disputes,
;; whistleblower document protection, regulatory audit trails, and contract
;; timestamping. Verification happens trustlessly-any party can confirm authenticity
;; using only the hash, without accessing or revealing the original content.
;; By leveraging Stacks' Bitcoin settlement guarantees, ChainProof delivers
;; institutional-grade security with public blockchain transparency, creating
;; a new paradigm for digital evidence and intellectual property protection.
;;
;; TL;DR:
;; Bitcoin-backed document notarization. Hash your files, anchor them permanently
;; to Bitcoin via Stacks, verify authenticity anytime without exposing content.
;; Perfect for patents, legal evidence, and compliance-no middlemen, no expiration.
;;

;; CONSTANTS & ERROR CODES

;; Error definitions
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_INVALID_MESSAGE (err u101))
(define-constant ERR_MESSAGE_NOT_FOUND (err u102))
(define-constant ERR_INVALID_HASH (err u103))
(define-constant ERR_INVALID_RECIPIENT (err u104))
(define-constant ERR_INVALID_VERSION (err u105))
(define-constant ERR_SELF_ATTESTATION (err u106))

;; Protocol constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant NULL_ADDRESS 'SP000000000000000000002Q6VF78)

;; STATE VARIABLES

(define-data-var total-attestations uint u0)
(define-data-var protocol-version uint u1)

;; DATA MAPS

;; Primary attestation ledger - immutable proof records
(define-map attestations
  { attestation-id: uint }
  {
    originator: principal,
    recipient: principal,
    content-hash: (buff 32),
    timestamp: uint,
    block-height: uint,
    verification-status: bool
  }
)

;; User activity tracking
(define-map user-attestation-count
  { user: principal }
  { count: uint }
)

;; Hash registry for reverse lookups and audit trails
(define-map hash-verification-registry
  { content-hash: (buff 32) }
  { 
    attestation-id: uint,
    verification-attempts: uint
  }
)

;; PRIVATE HELPER FUNCTIONS

(define-private (is-valid-hash (hash (buff 32)))
  (> (len hash) u0)
)

(define-private (is-valid-principal (user principal))
  (not (is-eq user NULL_ADDRESS))
)

(define-private (increment-attestation-count (user principal))
  (let 
    (
      (current-count (default-to u0 
        (get count (map-get? user-attestation-count { user: user }))
      ))
    )
    (map-set user-attestation-count 
      { user: user }
      { count: (+ current-count u1) }
    )
  )
)

;; PUBLIC CORE FUNCTIONS

;; @desc: Creates an immutable attestation record anchored to Bitcoin through Stacks.
;;        Establishes cryptographic proof of document existence at a specific block
;;        height by storing its SHA-256 hash on-chain, creating a verifiable chain
;;        of custody between originator and recipient without exposing content.
;;
;; @param recipient: Principal receiving the attestation (must differ from sender)
;; @param content-hash: 32-byte SHA-256 hash of the content being notarized
;;
;; @returns: (response uint uint) - Unique attestation ID on success
;;
;; Security: Prevents self-attestation, validates hash format and principal integrity
(define-public (create-attestation 
  (recipient principal) 
  (content-hash (buff 32))
)
  (let 
    (
      (attestation-id (+ (var-get total-attestations) u1))
      (current-block stacks-block-height)
    )
    ;; Validation checks
    (asserts! (is-valid-principal recipient) ERR_INVALID_RECIPIENT)
    (asserts! (is-valid-hash content-hash) ERR_INVALID_HASH)
    (asserts! (not (is-eq tx-sender recipient)) ERR_SELF_ATTESTATION)
    
    ;; Store attestation with metadata
    (map-set attestations
      { attestation-id: attestation-id }
      {
        originator: tx-sender,
        recipient: recipient,
        content-hash: content-hash,
        timestamp: current-block,
        block-height: current-block,
        verification-status: false
      }
    )
    
    ;; Create hash index for reverse lookups
    (map-set hash-verification-registry
      { content-hash: content-hash }
      {
        attestation-id: attestation-id,
        verification-attempts: u1
      }
    )
    
    ;; Update state
    (var-set total-attestations attestation-id)
    (increment-attestation-count tx-sender)
    
    (ok attestation-id)
  )
)

;; @desc: Performs zero-knowledge verification by comparing a provided hash against
;;        the stored attestation record. Confirms document authenticity without
;;        accessing original content, preserving privacy while proving integrity.
;;        Updates verification status and increments audit counter on success.
;;
;; @param attestation-id: Unique identifier of the attestation to verify
;; @param provided-hash: Hash to validate against the on-chain record
;;
;; @returns: (response bool uint) - true if hashes match, false otherwise
;;
;; Security: Validates attestation existence and hash format before comparison
(define-public (verify-attestation 
  (attestation-id uint) 
  (provided-hash (buff 32))
)
  (let 
    (
      (attestation-record (unwrap! 
        (map-get? attestations { attestation-id: attestation-id }) 
        ERR_MESSAGE_NOT_FOUND
      ))
      (stored-hash (get content-hash attestation-record))
    )
    ;; Input validation
    (asserts! (is-valid-hash provided-hash) ERR_INVALID_HASH)
    (asserts! (> attestation-id u0) ERR_INVALID_MESSAGE)
    
    (if (is-eq stored-hash provided-hash)
      (begin
        ;; Mark as verified
        (map-set attestations
          { attestation-id: attestation-id }
          (merge attestation-record { verification-status: true })
        )
        
        ;; Update verification counter
        (let 
          (
            (registry-entry (default-to 
              { attestation-id: u0, verification-attempts: u0 } 
              (map-get? hash-verification-registry { content-hash: provided-hash })
            ))
          )
          (map-set hash-verification-registry
            { content-hash: provided-hash }
            {
              attestation-id: attestation-id,
              verification-attempts: (+ (get verification-attempts registry-entry) u1)
            }
          )
        )
        (ok true)
      )
      (ok false)
    )
  )
)

;; @desc: Updates protocol version number (owner-only).
;;        Enforces version increment to prevent downgrades.
;;
;; @param new-version: New semantic version number (must be greater than current)
;;
;; @returns: (response bool uint) - Success status
;;
;; Security: Restricted to contract owner, validates version progression
(define-public (update-protocol-version (new-version uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (> new-version (var-get protocol-version)) ERR_INVALID_VERSION)
    (var-set protocol-version new-version)
    (ok true)
  )
)

;; READ-ONLY QUERY FUNCTIONS

;; @desc: Retrieves complete attestation record including originator, recipient,
;;        hash, timestamp, block height, and verification status.
;;
;; @param attestation-id: Target attestation identifier
;;
;; @returns: (response (optional {...}) uint) - Full attestation data or none
(define-read-only (get-attestation-info (attestation-id uint))
  (begin
    (asserts! (> attestation-id u0) ERR_INVALID_MESSAGE)
    (ok (map-get? attestations { attestation-id: attestation-id }))
  )
)

;; @desc: Returns total number of attestations created by a specific user.
;;
;; @param user: Principal to query
;;
;; @returns: (response uint uint) - Count of user's attestations
(define-read-only (get-user-attestation-count (user principal))
  (begin
    (asserts! (is-valid-principal user) ERR_INVALID_RECIPIENT)
    (ok (default-to u0 
      (get count (map-get? user-attestation-count { user: user }))
    ))
  )
)

;; @desc: Returns protocol-wide attestation counter.
;;
;; @returns: (response uint uint) - Total attestations since deployment
(define-read-only (get-total-attestations)
  (ok (var-get total-attestations))
)

;; @desc: Returns current protocol version for compatibility checking.
;;
;; @returns: (response uint uint) - Semantic version number
(define-read-only (get-protocol-version)
  (ok (var-get protocol-version))
)

;; @desc: Checks if a hash exists in the attestation registry.
;;
;; @param hash: 32-byte SHA-256 digest to check
;;
;; @returns: (response bool uint) - true if hash is registered, false otherwise
(define-read-only (hash-exists (hash (buff 32)))
  (begin
    (asserts! (is-valid-hash hash) ERR_INVALID_HASH)
    (ok (is-some (map-get? hash-verification-registry { content-hash: hash })))
  )
)

;; @desc: Retrieves total verification attempts for a specific hash.
;;        Useful for audit trails and attestation usage analytics.
;;
;; @param hash: Content hash to query
;;
;; @returns: (response uint uint) - Number of verification attempts
(define-read-only (get-verification-attempts (hash (buff 32)))
  (begin
    (asserts! (is-valid-hash hash) ERR_INVALID_HASH)
    (ok (default-to u0 
      (get verification-attempts 
        (map-get? hash-verification-registry { content-hash: hash })
      )
    ))
  )
)
