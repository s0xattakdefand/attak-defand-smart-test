// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract RootAttackAndDefense {
    address public immutable ROOT;
    mapping(address => bool) public claimed;
    bytes32 public trustedMerkleRoot;
    bool public claimClosed;

    event RootCompromised(address attacker);
    event RootProofAccepted(address user);
    event ClaimFinalized(address root);

    constructor(bytes32 _merkleRoot) {
        ROOT = msg.sender;
        trustedMerkleRoot = _merkleRoot;
    }

    // 🔥 1️⃣ Rootless Takeover Attack
    function initializeWithoutRoot() external {
        require(ROOT == address(0), "Already initialized");
        emit RootCompromised(msg.sender); // No longer possible due to immutable ROOT
    }

    // 🔥 2️⃣ Fake Merkle Root Forgery
    function claimWithFakeProof(bytes32[] calldata proof, bytes32 leaf) external {
        require(!claimClosed, "Claim closed");
        bytes32 computed = leaf;
        for (uint i = 0; i < proof.length; i++) {
            computed = keccak256(abi.encodePacked(computed, proof[i]));
        }
        require(computed == trustedMerkleRoot, "Invalid proof");
        require(!claimed[msg.sender], "Already claimed");
        claimed[msg.sender] = true;
        emit RootProofAccepted(msg.sender);
    }

    // 🔥 3️⃣ Root Delegatecall Backdoor
    fallback() external {
        require(msg.sender == ROOT, "Only root may call fallback");
        emit RootCompromised(msg.sender); // Example backdoor
    }

    // 🛡️ Immutable Root Owner Access
    modifier onlyRoot() {
        require(msg.sender == ROOT, "Not root");
        _;
    }

    // 🛡️ Finalize Root Ownership after Claim Window
    function finalizeClaimWindow() external onlyRoot {
        claimClosed = true;
        emit ClaimFinalized(msg.sender);
    }

    // 🛡️ Root Mutation Protection (Merkle proof root reset)
    function updateMerkleRoot(bytes32 newRoot) external onlyRoot {
        trustedMerkleRoot = newRoot;
    }

    // 🛡️ Guarded Privileged Function
    function privilegedLogic() external onlyRoot {
        // Critical logic (mint, upgrade, delegate)
    }
}
