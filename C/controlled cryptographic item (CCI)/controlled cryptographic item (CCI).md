### 🔐 Term: **Controlled Cryptographic Item (CCI)**

---

### 1. **What is a Controlled Cryptographic Item (CCI)?**

A **Controlled Cryptographic Item (CCI)** in the context of smart contracts refers to any **onchain or offchain cryptographic material** that must be **securely managed, accessed, or updated** under strict access control and lifecycle constraints.

This may include:

* Private/public key pairs
* Secret shares or commit-reveal hashes
* Encrypted data (e.g., secrets stored in decentralized storage)
* Signing keys used in ZKPs or MetaTx
* Nonces, salts, initialization vectors (IVs)

> 💡 In Web3, a CCI is like a **classified crypto “keycard”** — only verified parties can access or use it, and it must be revoked or rotated securely.

---

### 2. **Types of Controlled Cryptographic Items in Web3**

| Type                         | Description                                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------------------- |
| **Onchain Key Commitments**  | Stored hash of a secret value (e.g., for commit-reveal games or auctions).                  |
| **Signature Keys**           | Offchain keys used to sign messages (e.g., EIP-712, ECDSA).                                 |
| **ZK Keys**                  | Trusted setup or proving/verifying keys in ZK systems.                                      |
| **VRF Seeds**                | Seeds used to derive randomness securely (e.g., Chainlink VRF).                             |
| **Oracle Encryption Keys**   | Public keys used by oracles to encrypt data for onchain use.                                |
| **Hash-Based Access Tokens** | Preimage proofs to unlock actions or roles (e.g., hashed password for self-authentication). |

---

### 3. **Attack Types on CCI**

| Attack Type                   | Description                                              |
| ----------------------------- | -------------------------------------------------------- |
| **Replay Attack**             | Reusing a valid signature or nonce multiple times.       |
| **Preimage Attack**           | Brute-forcing a committed hash value to bypass access.   |
| **Key Exposure**              | Leaked keys give attackers full control.                 |
| **Spoofed Signature**         | Forged or invalid signature mimics a valid user.         |
| **Improper Zeroization**      | Sensitive values remain accessible in storage after use. |
| **Uncontrolled Key Rotation** | Malicious actor swaps in compromised keys.               |

---

### 4. **Defense Types for CCI**

| Defense Type             | Description                                              |
| ------------------------ | -------------------------------------------------------- |
| **Key Access Control**   | Limit who can update or use keys (RBAC, ownership).      |
| **Signature Validation** | Use ECDSA recovery + session nonces to validate signers. |
| **Hash Preimage Checks** | Require user to prove knowledge of preimage for access.  |
| **Storage Zeroization**  | Wipe storage once key is used or expired.                |
| **Event Audit Trails**   | Emit logs on key use, rotation, or failure.              |
| **Timelocked Rotation**  | Delay key replacement via DAO or admin timelock.         |

---

### 5. ✅ Solidity Code: `ControlledCryptoItem.sol` — Preimage-Guarded CCI with Role Access

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// @title ControlledCryptoItem — Smart contract-managed cryptographic secret
contract ControlledCryptoItem is AccessControl {
    bytes32 public constant CCI_ADMIN = keccak256("CCI_ADMIN");
    bytes32 private cciHash;
    bool public used;

    event CCIInitialized(bytes32 indexed hash);
    event CCIAccessed(address indexed by, string label);
    event CCIRevoked(address indexed by);

    constructor(bytes32 _hash, address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CCI_ADMIN, admin);
        cciHash = _hash;
        emit CCIInitialized(_hash);
    }

    /// @notice Access the CCI only by revealing correct preimage
    function accessCCI(string calldata label, string calldata secret) external {
        require(!used, "CCI: already used");
        require(keccak256(abi.encodePacked(secret)) == cciHash, "CCI: invalid secret");
        used = true;
        emit CCIAccessed(msg.sender, label);
        // Use the secret (e.g., mint, unlock, etc.)
    }

    /// @notice Admin can revoke the CCI
    function revokeCCI() external onlyRole(CCI_ADMIN) {
        used = true;
        emit CCIRevoked(msg.sender);
    }

    /// @notice Replace secret hash with new one (timelock recommended offchain)
    function rotateCCI(bytes32 newHash) external onlyRole(CCI_ADMIN) {
        require(used, "CCI: must revoke before rotate");
        cciHash = newHash;
        used = false;
        emit CCIInitialized(newHash);
    }
}
```

---

### ✅ What This Implements

| Security Feature              | Description                             |
| ----------------------------- | --------------------------------------- |
| **Hash Preimage Access**      | Only someone with the secret can access |
| **One-Time Use Flag**         | Prevents reuse or brute-force           |
| **Admin Rotation/Revocation** | Only `CCI_ADMIN` can manage             |
| **Audit Events**              | Transparent logs of usage and updates   |
| **Immutable Default Setup**   | Pre-set `cciHash` at deploy time        |

---

### 🛡️ Real Use Cases

| Use Case               | Why CCI is Critical                                   |
| ---------------------- | ----------------------------------------------------- |
| Commit-Reveal Auctions | Bidder must prove knowledge of their committed value. |
| MetaTx Authorizations  | Preapproved signatures unlock user actions.           |
| zkApp Init Seeds       | Access allowed only with ZK-proof + preimage.         |
| DAO Key Exchange       | Commit new keys before rotation or usage.             |
| API Token Whitelist    | Derive keys offchain; prove possession onchain.       |

---

### 🧠 Summary

A **Controlled Cryptographic Item (CCI)**:

* ✅ Represents secret or sensitive cryptographic material
* ✅ Must be **managed, revoked, and rotated** carefully
* ✅ Defends against **spoofing, brute-forcing, and replay**
* ✅ Can be accessed via **proof-of-preimage**, **signatures**, or **ZK**

---

Would you like to integrate:

* 🔐 **EIP-712 Signature Access** to replace preimage?
* 🧠 **zkSNARK validation** of secret instead of `keccak256`?
* ⛓ **Chainlink Keeper integration** to auto-expire unused CCIs?

Let me know your next focus.
