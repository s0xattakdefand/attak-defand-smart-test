// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ===================================== */
/*        ROOT TYPES IN SOLIDITY         */
/* ===================================== */

/*
1️⃣ Immutable Root Owner
Use case: Hardcoded superuser set at deployment, never changes
*/
contract ImmutableRootOwner {
    address public immutable ROOT;

    constructor() {
        ROOT = msg.sender;
    }

    modifier onlyRoot() {
        require(msg.sender == ROOT, "Not root");
        _;
    }

    function rootProtectedAction() external onlyRoot {
        // Root-only logic here
    }
}

/*
2️⃣ Mutable Root Role
Use case: Upgradeable admin/DAO-based systems
*/
contract MutableRootRole {
    mapping(address => bool) public isRoot;

    constructor() {
        isRoot[msg.sender] = true;
    }

    modifier onlyRoot() {
        require(isRoot[msg.sender], "Access denied");
        _;
    }

    function grantRoot(address user) external onlyRoot {
        isRoot[user] = true;
    }

    function revokeRoot(address user) external onlyRoot {
        isRoot[user] = false;
    }

    function rootCommand() external onlyRoot {
        // Mutable root-controlled logic
    }
}

/*
3️⃣ Merkle/ZK Root
Use case: zk-SNARK or Merkle tree proof-based authentication
*/
contract MerkleRootAccess {
    bytes32 public merkleRoot;

    constructor(bytes32 _root) {
        merkleRoot = _root;
    }

    function verifyProof(bytes32[] calldata proof, bytes32 leaf) public view returns (bool valid) {
        bytes32 computed = leaf;
        for (uint i = 0; i < proof.length; i++) {
            computed = keccak256(abi.encodePacked(computed, proof[i]));
        }
        return computed == merkleRoot;
    }

    function claim(bytes32[] calldata proof, bytes32 leaf) external {
        require(verifyProof(proof, leaf), "Invalid proof");
        // Access granted by zk/Merkle root
    }
}

/*
4️⃣ Root via Initializer (used in upgradeable proxy pattern)
Use case: Upgradeable systems with post-deploy root assignment
*/
contract InitializableRoot {
    address public root;
    bool public initialized;

    modifier onlyRoot() {
        require(msg.sender == root, "Only root");
        _;
    }

    function initialize(address _root) external {
        require(!initialized, "Already initialized");
        root = _root;
        initialized = true;
    }

    function securedAction() external onlyRoot {
        // Post-init root-only logic
    }
}

/*
5️⃣ Rootless (Vulnerable)
Use case: Deployer forgot to assign root or set as external-only
*/
contract RootlessVulnerable {
    address public root;

    function unprotectedTakeover() external {
        require(root == address(0), "Root already assigned");
        root = msg.sender; // 🧨 root claim without restriction
    }

    function rootRestricted() external {
        require(msg.sender == root, "Not root");
        // Exploitable if root wasn't set safely
    }
}
