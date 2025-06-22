// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConfidentialityImpactGuard — Detects and logs high-impact confidential events

contract ConfidentialityImpactGuard {
    address public owner;

    mapping(bytes32 => bool) public leakedSecrets;
    event HighImpactBreach(bytes32 indexed leakId, string category, address indexed reporter);
    event SecretFlagged(bytes32 indexed hash, string label);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// ✅ Anyone can report suspected high-impact leak (e.g., leaked config hash, strategy)
    function reportLeak(bytes32 leakHash, string calldata category) external {
        require(!leakedSecrets[leakHash], "Already reported");
        leakedSecrets[leakHash] = true;
        emit HighImpactBreach(leakHash, category, msg.sender);
    }

    /// 🔒 Admin can flag known secrets for tracking
    function flagSecret(bytes32 hash, string calldata label) external onlyOwner {
        emit SecretFlagged(hash, label);
    }

    /// View function: has this secret been leaked?
    function isLeaked(bytes32 hash) external view returns (bool) {
        return leakedSecrets[hash];
    }
}
