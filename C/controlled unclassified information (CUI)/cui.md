### 🔐 Term: **Controlled Unclassified Information (CUI)** in Web3 Smart Contracts

---

### ✅ Definition

**Controlled Unclassified Information (CUI)** refers to sensitive data that isn’t classified under national security laws but still requires safeguarding. In smart contracts, this can map to **data that is not encrypted but must be restricted**, such as:

* Private user metadata
* Internal project roles
* DAO governance plans
* Offchain secrets linked onchain (IPFS, oracles)
* Role-based business logic indicators

In Solidity, handling CUI involves **storage access control, encryption references, obfuscation**, and **offchain/onchain access rules**.

---

### 🔣 1. Types of CUI in Smart Contracts

| Type                        | Description                                 |
| --------------------------- | ------------------------------------------- |
| **User Identity Metadata**  | Email, role, offchain auth hash             |
| **Governance Preferences**  | Hidden votes, proposal prep data            |
| **DAO Treasury Plans**      | Budget logic not yet public                 |
| **Encrypted Data Pointers** | IPFS/Arweave links, zkFiles                 |
| **Confidential Role Flags** | Admin flags for staged upgrades             |
| **ZK-Gated Info**           | Enforced via ZK proof instead of open state |

---

### 🚨 2. Attack Types on CUI

| Attack Type                | Target           | Description                         |
| -------------------------- | ---------------- | ----------------------------------- |
| **Unrestricted Access**    | Public read view | Anyone can query `public` vars      |
| **Storage Leaks**          | Structs/mappings | Poor layout reveals internal data   |
| **Hash Reversal**          | Hashed metadata  | Weak entropy or dictionary reversal |
| **Offchain Link Snooping** | IPFS/Arweave     | Extracting data from exposed URLs   |
| **Role Leak via Revert**   | Role checks      | Revert msg reveals sensitive logic  |
| **Metadata Replay**        | Offchain relays  | Reusing signed confidential actions |

---

### 🛡️ 3. Defense Techniques for CUI

| Defense Type               | Description                                     |
| -------------------------- | ----------------------------------------------- |
| **Private Mappings**       | Use internal mappings over public state         |
| **Hashed Identifiers**     | Store hashes of data, not raw values            |
| **ZK Proof Access**        | Require a ZK proof to read sensitive output     |
| **Offchain Encryption**    | Encrypt offchain data, reveal by keys only      |
| **Obfuscated Roles/Flags** | Avoid exposing internal logic to external calls |
| **Access Control**         | Use `AccessControl` to gate access to metadata  |

---

### ✅ 4. Solidity Example: `CUIProtectedStorage.sol`

Includes:

* Role-gated access to CUI
* Secure storage with hashed keys
* Events with redacted metadata

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract CUIProtectedStorage is AccessControl {
    bytes32 public constant INFO_WRITER = keccak256("INFO_WRITER");
    mapping(bytes32 => bytes32) private secureData; // keyHash => dataHash

    event CUIStored(bytes32 indexed keyHash, address indexed by);
    event AccessDenied(address indexed by, string reason);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(INFO_WRITER, admin);
    }

    /// @notice Store CUI (hashed key and value)
    function storeCUI(bytes32 keyHash, bytes32 valueHash) external onlyRole(INFO_WRITER) {
        secureData[keyHash] = valueHash;
        emit CUIStored(keyHash, msg.sender);
    }

    /// @notice Read CUI value (only admin)
    function getCUI(bytes32 keyHash) external view onlyRole(DEFAULT_ADMIN_ROLE) returns (bytes32) {
        return secureData[keyHash];
    }

    /// @notice Reject public access
    fallback() external payable {
        emit AccessDenied(msg.sender, "fallback");
        revert("Denied");
    }

    receive() external payable {
        emit AccessDenied(msg.sender, "ether rejected");
        revert("No Ether");
    }
}
```

---

### 🔐 Summary: Handling CUI in Solidity

| Protection Strategy      | How It Works                       |
| ------------------------ | ---------------------------------- |
| Hashed Keys/Values       | Avoids exposing raw sensitive info |
| Role-Gated Access        | Admins or designated roles only    |
| Revert Logging           | Catch and log unauthorized access  |
| IPFS/zkProof Optionality | Keep data offchain, check via ZK   |
| Struct Obfuscation       | Store redacted metadata per user   |

---

### 🔁 Optional Enhancements

Would you like to:

* 🔐 Add encryption hooks to link with zkIPFS?
* 🧠 Log access attempts with AI scoring (e.g. anomaly triggers)?
* 🗃 Build a cross-contract CUI registry?

Let me know the next layer of protection or functionality, and I’ll expand this system.
