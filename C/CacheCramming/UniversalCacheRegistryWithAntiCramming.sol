// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./UniversalCacheRegistry.sol";

interface IZKWriterVerifier {
    function isVerified(address user, bytes calldata proof) external view returns (bool);
}

contract UniversalCacheRegistryWithAntiCramming is UniversalCacheRegistry {
    mapping(address => uint256) public writeCounts;
    uint256 public writeLimit = 10;
    uint256 public writeFee = 0.01 ether;
    address public zkVerifier;

    event WriteLimitReached(address user);
    event ZKVerificationFailed(address user);

    constructor(address initialOwner, address _zkVerifier) UniversalCacheRegistry(initialOwner) {
        zkVerifier = _zkVerifier;
    }

    modifier notCramming() {
        require(writeCounts[msg.sender] < writeLimit, "[Cache] Write limit reached");
        _;
    }

    function setWriteLimit(uint256 limit) external onlyOwner {
        writeLimit = limit;
    }

    function setWriteFee(uint256 fee) external onlyOwner {
        writeFee = fee;
    }

    function setZKVerifier(address verifier) external onlyOwner {
        zkVerifier = verifier;
    }

    function updateCacheWithFee(bytes32 key, bytes calldata data) external payable notCramming {
        require(msg.value >= writeFee, "[Cache] Insufficient fee");
        writeCounts[msg.sender]++;
        updateCache(key, data);
    }

    function updateCacheWithZKProof(bytes32 key, bytes calldata data, bytes calldata proof) external notCramming {
        require(zkVerifier != address(0), "[Cache] No verifier set");
        bool verified = IZKWriterVerifier(zkVerifier).isVerified(msg.sender, proof);
        require(verified, "[Cache] ZK proof invalid");
        writeCounts[msg.sender]++;
        updateCache(key, data);
    }

    function resetWriteCount(address user) external onlyOwner {
        writeCounts[user] = 0;
    }
}
