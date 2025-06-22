// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ARMComputeVerifier — Validate compute outputs from ARM/RISC systems
contract ARMComputeVerifier {
    address public verifierAdmin;

    struct ComputeJob {
        bytes32 outputHash; // keccak256(result or zkProof output)
        uint256 timestamp;
        bool verified;
    }

    mapping(address => ComputeJob[]) public computeLogs;

    event JobSubmitted(address indexed user, uint256 jobId, bytes32 outputHash);
    event JobVerified(address indexed user, uint256 jobId);

    modifier onlyAdmin() {
        require(msg.sender == verifierAdmin, "Not authorized");
        _;
    }

    constructor() {
        verifierAdmin = msg.sender;
    }

    /// Submit offchain-computed result (e.g., ARM simulation hash)
    function submitJob(bytes32 outputHash) external returns (uint256) {
        computeLogs[msg.sender].push(ComputeJob(outputHash, block.timestamp, false));
        uint256 jobId = computeLogs[msg.sender].length - 1;
        emit JobSubmitted(msg.sender, jobId, outputHash);
        return jobId;
    }

    /// Admin/zkVerifier confirms result as valid
    function verifyJob(address user, uint256 jobId) external onlyAdmin {
        computeLogs[user][jobId].verified = true;
        emit JobVerified(user, jobId);
    }

    function getJob(address user, uint256 jobId) external view returns (ComputeJob memory) {
        return computeLogs[user][jobId];
    }
}
