// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AlgorithmSecurityLifetime {
    struct AlgoLifetime {
        uint256 startTime;
        uint256 endTime;
        bool active;
    }

    mapping(bytes32 => AlgoLifetime) public algorithmRegistry;

    event AlgorithmRegistered(bytes32 indexed algoId, uint256 start, uint256 end);
    event AlgorithmExpired(bytes32 indexed algoId);

    modifier isValidLifetime(bytes32 algoId) {
        AlgoLifetime memory a = algorithmRegistry[algoId];
        require(a.active, "Algorithm not active");
        require(block.timestamp >= a.startTime, "Not yet valid");
        require(block.timestamp <= a.endTime, "Algorithm expired");
        _;
    }

    function registerAlgorithm(bytes32 algoId, uint256 start, uint256 end) external {
        require(end > start, "Invalid lifetime");
        algorithmRegistry[algoId] = AlgoLifetime(start, end, true);
        emit AlgorithmRegistered(algoId, start, end);
    }

    function isAlgorithmSecure(bytes32 algoId) public view returns (bool) {
        AlgoLifetime memory a = algorithmRegistry[algoId];
        return a.active && block.timestamp >= a.startTime && block.timestamp <= a.endTime;
    }

    function markAsExpired(bytes32 algoId) external {
        AlgoLifetime storage a = algorithmRegistry[algoId];
        require(a.active, "Not active");
        a.endTime = block.timestamp;
        a.active = false;
        emit AlgorithmExpired(algoId);
    }

    /// Example: gated function
    function verifyAction(bytes32 algoId, bytes calldata data) external view isValidLifetime(algoId) returns (bytes32) {
        return keccak256(data); // Simulated hash action gated by valid algorithm
    }
}
