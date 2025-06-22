### 🔐 Term: **Controlled Cryptographic Item (CCI) — Component Breakdown**

---

### ✅ Definition

A **Controlled Cryptographic Item (CCI)** **Component** refers to the **core sub-elements** that make up a cryptographic item which must be **carefully managed** in Web3 for **security, availability, and lifecycle correctness**.

In smart contracts, **CCI components** are often used in:

* Commit-reveal mechanisms
* Signature-based access control
* ZK rollups / proofs
* VRF-based randomness
* Secure module authentication

---

### 1. **Types of CCI Components in Web3**

| Component               | Description                                                           |
| ----------------------- | --------------------------------------------------------------------- |
| 🔑 **Key Material**     | Public/Private key pair or ECDSA/ECDH keys for signing or encryption  |
| 🔐 **Commit Hash**      | A `keccak256` hash of a secret/preimage used for secure reveal later  |
| 🧂 **Salt/Nonce**       | Random value used to prevent replay or rainbow table attacks          |
| 🧬 **Derived Key**      | Key derived from shared secret using KDF (e.g., HMAC, HKDF)           |
| 🧾 **Signature**        | ECDSA (r, s, v) triplet to verify origin of a message                 |
| ⏱ **Expiry Block/Time** | Block number or timestamp limiting key or secret validity             |
| 🧼 **Zeroization Flag** | Boolean or status indicating if item was used/cleared                 |
| 🧱 **Storage Slot**     | Custom low-level slot for secure storage of secrets or key components |
| 🔁 **Rotation Policy**  | Mechanism that governs when and how to rotate a CCI                   |

---

### 2. **Attack Types Targeting CCI Components**

| Attack Type            | Target Component           | Description                                               |
| ---------------------- | -------------------------- | --------------------------------------------------------- |
| **Signature Spoofing** | Signature                  | Forged or reused signature to bypass auth                 |
| **Replay Attack**      | Nonce / Expiry             | Reusing same valid message multiple times                 |
| **Preimage Discovery** | Commit Hash                | Brute-force of hash to find matching secret               |
| **Key Leakage**        | Key Material / Derived Key | Compromised key gives attacker full access                |
| **Storage Drift**      | Storage Slot               | Overlapping slots during upgrade leads to data corruption |
| **Weak KDF Logic**     | Derived Key                | Poor derivation can allow predictable secrets             |

---

### 3. **Defense Mechanisms for CCI Components**

| Defense                      | Protected Component            | Description                                      |
| ---------------------------- | ------------------------------ | ------------------------------------------------ |
| **ECDSA Validation + Nonce** | Signature / Nonce              | Prevent replay and signature reuse               |
| **Commit/Reveal + Expiry**   | Commit Hash / Expiry           | Only valid during short time window              |
| **StorageSlot Isolation**    | Storage Slot                   | Use `StorageSlot` lib to avoid collision         |
| **Key Rotation + Audit**     | Key Material / Rotation Policy | Change keys regularly and log access             |
| **Zeroization Routine**      | Zeroization Flag               | Explicit clearing after use                      |
| **KDF Best Practices**       | Derived Key                    | Use strong entropy, never reuse salts or secrets |

---

### 4. ✅ Solidity Implementation: `CCIComponentVault.sol`

This example contract demonstrates:

* Storage of CCI hash and ECDSA signature validation
* One-time use (zeroization)
* Expiry block enforcement
* Key rotation with audit logs

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";

contract CCIComponentVault {
    using ECDSA for bytes32;

    bytes32 private constant CCI_SLOT = keccak256("cci.component.slot");
    bytes32 private constant USED_SLOT = keccak256("cci.component.used");
    address public immutable trustedSigner;
    uint256 public expiryBlock;

    event AccessGranted(address indexed user);
    event CCIUsed(address indexed by);
    event CCIRotated(bytes32 newCCIHash);
    event CCIZeroized();

    constructor(bytes32 _cciHash, address _signer, uint256 _expiryBlock) {
        StorageSlot.getBytes32Slot(CCI_SLOT).value = _cciHash;
        trustedSigner = _signer;
        expiryBlock = _expiryBlock;
    }

    modifier notExpired() {
        require(block.number <= expiryBlock, "CCI: expired");
        _;
    }

    modifier notUsed() {
        require(!StorageSlot.getBooleanSlot(USED_SLOT).value, "CCI: already used");
        _;
    }

    function accessCCI(string calldata secret, bytes calldata signature)
        external
        notExpired
        notUsed
    {
        bytes32 hash = keccak256(abi.encodePacked(secret)).toEthSignedMessageHash();
        require(hash.recover(signature) == trustedSigner, "CCI: invalid signer");

        require(
            keccak256(abi.encodePacked(secret)) == StorageSlot.getBytes32Slot(CCI_SLOT).value,
            "CCI: secret mismatch"
        );

        StorageSlot.getBooleanSlot(USED_SLOT).value = true;

        emit AccessGranted(msg.sender);
        emit CCIUsed(msg.sender);
    }

    function rotateCCI(bytes32 newHash) external {
        require(msg.sender == trustedSigner, "Not authorized");
        StorageSlot.getBytes32Slot(CCI_SLOT).value = newHash;
        StorageSlot.getBooleanSlot(USED_SLOT).value = false;
        emit CCIRotated(newHash);
    }

    function zeroizeCCI() external {
        require(msg.sender == trustedSigner, "Not authorized");
        StorageSlot.getBytes32Slot(CCI_SLOT).value = bytes32(0);
        StorageSlot.getBooleanSlot(USED_SLOT).value = true;
        emit CCIZeroized();
    }
}
```

---

### ✅ Summary

| CCI Component   | Implementation                            |
| --------------- | ----------------------------------------- |
| `cciHash`       | Stored securely in isolated storage slot  |
| `trustedSigner` | Used to verify ECDSA signature for origin |
| `expiryBlock`   | Ensures temporal validity                 |
| `USED_SLOT`     | Boolean flag for one-time-use logic       |
| `rotateCCI()`   | Allows rotation by authorized signer      |
| `zeroizeCCI()`  | Secure deletion of hash + usage flag      |

---

### 🔄 Optional Enhancements

| Add-on                     | Purpose                                      |
| -------------------------- | -------------------------------------------- |
| 🔐 Poseidon Hash Support   | For zkSNARK-compatible secrets               |
| ⏳ DAO Timelock Rotation    | Requires proposal to change key              |
| 🧠 Multi-Sig Admin Access  | Prevent single point of failure for rotation |
| 🌐 Chainlink Keeper Expiry | Auto-expire onchain via oracle monitoring    |

---

Would you like to:

* Integrate this into a **zk-proof circuit**?
* Add **multi-use key tracking** with usage limits?
* Simulate a **replay attack** and test the defense?

Let me know your next step.
