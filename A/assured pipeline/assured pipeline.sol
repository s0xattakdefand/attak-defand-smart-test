// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AssuredPipelineExecutor {
    struct PipelineStep {
        string label;
        bytes32 expectedHash;
        bool completed;
    }

    mapping(uint256 => PipelineStep) public steps;
    uint256 public stepCount;
    uint256 public currentStep;

    event StepCompleted(uint256 indexed step, string label, bytes32 resultHash);
    event TamperDetected(uint256 indexed step, string label, bytes32 wrongHash);

    constructor(string[] memory labels, bytes32[] memory hashes) {
        require(labels.length == hashes.length, "Mismatch");
        stepCount = labels.length;

        for (uint i = 0; i < stepCount; i++) {
            steps[i] = PipelineStep(labels[i], hashes[i], false);
        }
    }

    function completeStep(string calldata label, bytes calldata result) external {
        require(currentStep < stepCount, "Pipeline complete");
        PipelineStep storage step = steps[currentStep];
        require(keccak256(abi.encodePacked(label)) == keccak256(abi.encodePacked(step.label)), "Wrong label");

        bytes32 resultHash = keccak256(result);

        if (resultHash != step.expectedHash) {
            emit TamperDetected(currentStep, label, resultHash);
            revert("Pipeline tampering detected");
        }

        step.completed = true;
        emit StepCompleted(currentStep, label, resultHash);
        currentStep++;
    }

    function getPipelineStatus() external view returns (uint256 total, uint256 completed) {
        return (stepCount, currentStep);
    }

    function isFinalized() external view returns (bool) {
        return currentStep == stepCount;
    }
}
