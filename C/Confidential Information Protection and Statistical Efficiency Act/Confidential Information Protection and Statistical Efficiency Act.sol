// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAggregateVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata publicInputs
    ) external view returns (bool);
}

/// @title StatisticalDisclosureGuard — Ensures confidential statistical submissions follow CIPSEA-like privacy rules
contract StatisticalDisclosureGuard {
    IAggregateVerifier public verifier;
    address public owner;

    struct Submission {
        bool consented;
        bytes32 encryptedRecord;
    }

    mapping(address => Submission) public userData;
    mapping(bytes32 => bool) public usedProofs;

    event DataSubmitted(address indexed user);
    event AggregateProofAccepted(bytes32 indexed reportId);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor(address verifierAddress) {
        verifier = IAggregateVerifier(verifierAddress);
        owner = msg.sender;
    }

    /// ✅ User submits encrypted data and gives consent
    function submitData(bytes32 encryptedRecord, bool consent) external {
        userData[msg.sender] = Submission(consent, encryptedRecord);
        emit DataSubmitted(msg.sender);
    }

    /// ✅ ZK-verified aggregate stat, e.g., average salary with differential privacy
    function submitAggregateProof(
        bytes32 reportId,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata inputs
    ) external {
        require(!usedProofs[reportId], "Replay detected");
        bool valid = verifier.verifyProof(a, b, c, inputs);
        require(valid, "Invalid statistical proof");
        usedProofs[reportId] = true;
        emit AggregateProofAccepted(reportId);
    }

    /// Admin can revoke submission if needed
    function revokeUser(address user) external onlyOwner {
        delete userData[user];
    }
}
