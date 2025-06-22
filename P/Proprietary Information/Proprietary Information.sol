// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Internal Logic Function ========== */
contract ProprietaryLogic {
    address public admin;
    uint256 private algoFactor = 42;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Access denied");
        _;
    }

    function computeHidden(uint256 x) external view onlyAdmin returns (uint256) {
        return x * algoFactor + 1337;
    }
}

/* ========== 2️⃣ Private Whitelist Mapping ========== */
contract HiddenWhitelist {
    mapping(address => bool) private secretList;

    function toggle(address user, bool yes) external {
        secretList[user] = yes;
    }

    function isWhitelisted(address u) external view returns (bool) {
        return secretList[u];
    }
}

/* ========== 3️⃣ Encrypted Constant Loader ========== */
contract EncryptedConfig {
    bytes32 internal encrypted;

    function setEncrypted(bytes32 val) external {
        encrypted = val;
    }

    function getEncrypted() external view returns (bytes32) {
        return encrypted;
    }
}

/* ========== 4️⃣ zkProof-Based View Access ========== */
contract ZKBoundView {
    mapping(bytes32 => string) private data;

    function store(bytes32 zkID, string calldata secret) external {
        data[zkID] = secret;
    }

    function viewSecret(bytes32 zkID, bytes calldata zkProof) external view returns (string memory) {
        require(verifyZK(zkProof, zkID), "Invalid proof");
        return data[zkID];
    }

    function verifyZK(bytes calldata, bytes32) internal pure returns (bool) {
        // mock
        return true;
    }
}

/* ========== 5️⃣ Selector Firewall ========== */
contract SelectorGuard {
    mapping(bytes4 => bool) public allowed;

    function allow(bytes4 sel, bool ok) external {
        allowed[sel] = ok;
    }

    fallback() external {
        require(allowed[msg.sig], "Blocked selector");
    }
}
