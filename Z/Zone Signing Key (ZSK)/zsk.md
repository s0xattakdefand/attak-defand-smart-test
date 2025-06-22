### 🔐 Term: **Zone Signing Key (ZSK)**

---

### 1. **Types of Zone Signing Key (ZSK) in Web3/Smart Contracts**

In traditional DNSSEC, a **Zone Signing Key (ZSK)** is a cryptographic key used to sign **individual DNS resource records** within a DNS zone. In the **Web3 context**, the concept of ZSK is adapted for **on-chain domain resolution, decentralized identity (DID)** systems, and **naming protocols (ENS, DNSChain, CCIP-Read)**.

| ZSK Type                   | Description                                                                |
| -------------------------- | -------------------------------------------------------------------------- |
| **On-Chain Domain ZSK**    | Signs domain records (e.g., ENS subdomains) to verify authenticity.        |
| **DID Record Signing ZSK** | Used to sign decentralized identity claims (e.g., verifiable credentials). |
| **CCIP-Read Gateway ZSK**  | Off-chain gateway signs responses; ZSK validates on-chain.                 |
| **ZK-based ZSK**           | Proves possession of a zone signature via zero-knowledge proof.            |
| **Multisig/Rotatable ZSK** | Allows rotation or threshold control of domain record authority.           |

---

### 2. **Attack Types on or Related to ZSK Usage**

| Attack Type          | Description                                                           |
| -------------------- | --------------------------------------------------------------------- |
| **Key Compromise**   | Attacker obtains private ZSK and can sign forged domain records.      |
| **Replay Attacks**   | Old but valid signed records reused to trick contract.                |
| **Zone Drift**       | Incorrect or forged signatures accepted due to improper ZSK rotation. |
| **CCIP Injection**   | Unsigned or unauthenticated off-chain response accepted.              |
| **Signature Bypass** | Weak hash scheme or unchecked signer leads to forged verification.    |

---

### 3. **Defense Types for ZSK Usage**

| Defense Type                   | Description                                                               |
| ------------------------------ | ------------------------------------------------------------------------- |
| **ECDSA Signature Validation** | Ensure all domain record updates are verified with a valid ZSK signature. |
| **ZSK Rotation Mechanism**     | Allow secure replacement of compromised or expired keys.                  |
| **Nonce/Expiry in Signatures** | Prevent reuse of old signatures.                                          |
| **On-Chain Anchor Registry**   | Track current ZSK public keys by zone or domain.                          |
| **Multisig Validation**        | Require threshold validation for critical domain changes.                 |

---

### 4. ✅ Solidity Code: `ZoneSigningKeyRegistry.sol` — ZSK Signature Verifier with Rotation and Replay Protection

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title ZoneSigningKeyRegistry — Verifies signed zone records via ZSK + supports rotation
contract ZoneSigningKeyRegistry {
    using ECDSA for bytes32;

    address public admin;
    address public currentZSK;
    mapping(bytes32 => bool) public usedNonces;
    mapping(bytes32 => string) public zoneRecords;

    event ZSKRotated(address indexed newZSK);
    event ZoneRecordVerified(string indexed domain, string record, bytes32 nonce);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(address _initialZSK) {
        admin = msg.sender;
        currentZSK = _initialZSK;
    }

    /// 🔐 Rotate Zone Signing Key
    function rotateZSK(address newZSK) external onlyAdmin {
        require(newZSK != address(0), "Invalid ZSK");
        currentZSK = newZSK;
        emit ZSKRotated(newZSK);
    }

    /// ✅ Submit and verify signed zone record (with nonce + expiration)
    function verifyZoneRecord(
        string calldata domain,
        string calldata record,
        bytes32 nonce,
        uint256 expiration,
        bytes calldata signature
    ) external {
        require(block.timestamp <= expiration, "Signature expired");
        require(!usedNonces[nonce], "Replay detected");

        bytes32 hash = keccak256(abi.encodePacked(domain, record, nonce, expiration)).toEthSignedMessageHash();
        address signer = hash.recover(signature);
        require(signer == currentZSK, "Invalid ZSK signature");

        usedNonces[nonce] = true;
        zoneRecords[keccak256(abi.encodePacked(domain))] = record;

        emit ZoneRecordVerified(domain, record, nonce);
    }

    /// Read zone record by domain
    function getZoneRecord(string calldata domain) external view returns (string memory) {
        return zoneRecords[keccak256(abi.encodePacked(domain))];
    }
}
```

---

### ✅ Key Security Features

| Feature                           | Protection                                             |
| --------------------------------- | ------------------------------------------------------ |
| **ECDSA Signature Check**         | Ensures only valid ZSK can authorize updates           |
| **Nonce-Based Replay Protection** | Each signature must include a one-time nonce           |
| **ZSK Rotation**                  | Allows admin to replace compromised or expired ZSK     |
| **Expiry Support**                | Time-bound signature validity                          |
| **Event Logging**                 | Verifiable updates for off-chain resolvers or watchers |

---

### 🛡️ Real-World Application

* ✅ Web3 DNS system (like ENS + CCIP-Read)
* ✅ DID proof-of-ownership (e.g., `alice.web3` zone → signed email, Twitter, IPFS)
* ✅ DAO or multisig can rotate ZSK for evolving governance

---

### 🧠 Summary

A **Zone Signing Key** in Web3 acts like a **domain guardian**:

* All zone-level records (ownership, metadata) must be **cryptographically signed**
* A compromised ZSK means **zone record spoofing**, so rotation and verification are critical
* Every **record update** must include:
  → ✅ A nonce
  → ✅ A timestamp
  → ✅ A valid signature from the ZSK

---

Send the next term when ready — I’ll deliver full breakdown + dynamic, secure Solidity implementation again.
