// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AOUPValidator {
    struct AOUP {
        uint256 startTime;
        uint256 endTime;
        bool active;
    }

    mapping(address => AOUP) public signerAOUP;
    mapping(bytes32 => AOUP) public algorithmAOUP;

    event SignerRegistered(address signer, uint256 start, uint256 end);
    event AlgorithmRegistered(bytes32 algoId, uint256 start, uint256 end);

    modifier withinPeriod(address signer) {
        AOUP memory period = signerAOUP[signer];
        require(period.active, "Signer AOUP inactive");
        require(block.timestamp >= period.startTime, "Usage period not started");
        require(block.timestamp <= period.endTime, "Usage period expired");
        _;
    }

    function registerSigner(address signer, uint256 start, uint256 end) external {
        require(end > start, "Invalid AOUP window");
        signerAOUP[signer] = AOUP(start, end, true);
        emit SignerRegistered(signer, start, end);
    }

    function registerAlgorithm(bytes32 algoId, uint256 start, uint256 end) external {
        require(end > start, "Invalid AOUP window");
        algorithmAOUP[algoId] = AOUP(start, end, true);
        emit AlgorithmRegistered(algoId, start, end);
    }

    /// Example: Enforce AOUP before processing
    function validateSignerUsage(address signer) external view withinPeriod(signer) returns (bool) {
        return true;
    }

    function isAlgorithmValid(bytes32 algoId) external view returns (bool) {
        AOUP memory period = algorithmAOUP[algoId];
        return period.active && block.timestamp >= period.startTime && block.timestamp <= period.endTime;
    }
}
