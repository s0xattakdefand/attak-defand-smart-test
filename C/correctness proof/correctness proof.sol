// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CorrectnessProofVerifier {
    address public admin;

    struct ProofRecord {
        bytes32 expectedHash;
        bool verified;
        uint256 timestamp;
    }

    mapping(bytes32 => ProofRecord) public proofs;

    event ProofRegistered(bytes32 indexed sessionId, bytes32 expectedHash);
    event ProofVerified(bytes32 indexed sessionId, address verifier);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Register a proof expectation (e.g. off-chain zk result or formal check)
    function registerProof(bytes32 sessionId, bytes32 expectedHash) external onlyAdmin {
        require(proofs[sessionId].timestamp == 0, "Already registered");
        proofs[sessionId] = ProofRecord(expectedHash, false, block.timestamp);
        emit ProofRegistered(sessionId, expectedHash);
    }

    /// Submit the actual proof hash (e.g. zk output, signed data hash)
    function verifyProof(bytes32 sessionId, bytes32 submittedHash) external returns (bool) {
        ProofRecord storage p = proofs[sessionId];
        require(p.timestamp != 0, "Proof not registered");
        require(!p.verified, "Already verified");
        require(p.expectedHash == submittedHash, "Hash mismatch");

        p.verified = true;
        emit ProofVerified(sessionId, msg.sender);
        return true;
    }

    /// Public view of status
    function getProofStatus(bytes32 sessionId) external view returns (bool verified, uint256 timestamp) {
        ProofRecord memory p = proofs[sessionId];
        return (p.verified, p.timestamp);
    }
}
