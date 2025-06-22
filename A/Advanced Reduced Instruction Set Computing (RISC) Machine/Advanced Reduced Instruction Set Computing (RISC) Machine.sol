// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ARMProofVerifier — Verifies offchain ARM (RISC-style) program execution proof
contract ARMProofVerifier {
    address public verifierAdmin;

    struct ExecutionRecord {
        bytes32 outputHash;    // hash of final state/output
        address executor;
        bool verified;
        uint256 timestamp;
    }

    ExecutionRecord[] public executions;

    event ProofSubmitted(uint256 indexed id, address indexed executor, bytes32 outputHash);
    event ProofVerified(uint256 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == verifierAdmin, "Not authorized");
        _;
    }

    constructor() {
        verifierAdmin = msg.sender;
    }

    /// Simulated proof submission (e.g., from RISC Zero)
    function submitProof(bytes32 outputHash) external returns (uint256) {
        executions.push(ExecutionRecord(outputHash, msg.sender, false, block.timestamp));
        uint256 id = executions.length - 1;
        emit ProofSubmitted(id, msg.sender, outputHash);
        return id;
    }

    /// Simulate proof verification (zk proof matched offchain)
    function verifyProof(uint256 id, bytes32 expectedHash) external onlyAdmin {
        require(executions[id].outputHash == expectedHash, "Output hash mismatch");
        executions[id].verified = true;
        emit ProofVerified(id);
    }

    function getExecution(uint256 id) external view returns (ExecutionRecord memory) {
        return executions[id];
    }
}
