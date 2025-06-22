// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ConfidentialityModeSwitch {
    enum Mode { Public, Commitment, Encrypted, ZKProof, TrustedCompute }

    address public owner;
    Mode public currentMode;

    mapping(address => bytes32) public commitments;
    mapping(bytes32 => bool) public usedZKNullifiers;

    event ModeChanged(Mode newMode);
    event Committed(address indexed user, bytes32 hash);
    event ZKProofAccepted(address indexed user, bytes32 nullifier);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
        currentMode = Mode.Public;
    }

    function setMode(Mode newMode) external onlyOwner {
        currentMode = newMode;
        emit ModeChanged(newMode);
    }

    // 🔐 Example: Commitment Mode
    function submitCommitment(bytes32 hash) external {
        require(currentMode == Mode.Commitment, "Not in commitment mode");
        commitments[msg.sender] = hash;
        emit Committed(msg.sender, hash);
    }

    // 🔐 Example: ZK Proof Mode
    function submitZKProof(bytes32 nullifierHash) external {
        require(currentMode == Mode.ZKProof, "Not in ZK proof mode");
        require(!usedZKNullifiers[nullifierHash], "Nullifier replay");
        usedZKNullifiers[nullifierHash] = true;
        emit ZKProofAccepted(msg.sender, nullifierHash);
    }

    function getCurrentMode() external view returns (string memory) {
        if (currentMode == Mode.Public) return "Public";
        if (currentMode == Mode.Commitment) return "Commitment";
        if (currentMode == Mode.Encrypted) return "Encrypted";
        if (currentMode == Mode.ZKProof) return "ZKProof";
        if (currentMode == Mode.TrustedCompute) return "TrustedCompute";
        return "Unknown";
    }
}
