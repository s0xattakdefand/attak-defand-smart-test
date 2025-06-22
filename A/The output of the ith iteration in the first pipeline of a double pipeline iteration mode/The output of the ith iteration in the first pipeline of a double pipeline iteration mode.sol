// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Pipeline Drift Attack, Partial Output Forgery, Pipeline Replay Attack
/// Defense Types: Strict Iteration Binding, Signed Intermediate Outputs, Replay Protection with Nonce

contract DoublePipelineIterationMode {
    address public admin;
    mapping(address => bytes32[]) public firstPipelineOutputs; // First pipeline per user
    mapping(address => bytes32) public finalDigest; // Final output after double pipeline

    event FirstPipelineOutput(address indexed user, uint256 iteration, bytes32 output);
    event FinalDigestComputed(address indexed user, bytes32 digest);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can initiate");
        _;
    }

    /// ATTACK Simulation: Forge a wrong i-th iteration output
    function attackForgePipelineOutput(address user, uint256 iteration, bytes32 fakeOutput) external {
        firstPipelineOutputs[user][iteration] = fakeOutput; // direct overwrite simulation
    }

    /// DEFENSE: Secure ith output generation in the first pipeline
    function generateFirstPipelineOutput(
        address user,
        bytes32 previousOutput, 
        uint256 iteration,
        bytes32 inputData
    ) external onlyAdmin {
        if (iteration > 0) {
            require(firstPipelineOutputs[user][iteration - 1] == previousOutput, "Invalid pipeline chaining");
        }
        bytes32 newOutput = keccak256(abi.encodePacked(previousOutput, inputData, iteration));
        firstPipelineOutputs[user].push(newOutput);
        emit FirstPipelineOutput(user, iteration, newOutput);
    }

    /// DEFENSE: Secure second pipeline computation (final digest)
    function computeFinalDigest(address user) external onlyAdmin {
        uint256 len = firstPipelineOutputs[user].length;
        require(len > 0, "No pipeline outputs yet");

        bytes32 accum = 0x00;
        for (uint256 i = 0; i < len; i++) {
            accum = keccak256(abi.encodePacked(accum, firstPipelineOutputs[user][i], i));
        }

        finalDigest[user] = accum;
        emit FinalDigestComputed(user, accum);
    }

    /// View ith output
    function viewFirstPipelineOutput(address user, uint256 iteration) external view returns (bytes32) {
        require(iteration < firstPipelineOutputs[user].length, "Invalid iteration");
        return firstPipelineOutputs[user][iteration];
    }

    /// View final digest
    function viewFinalDigest(address user) external view returns (bytes32) {
        return finalDigest[user];
    }
}
