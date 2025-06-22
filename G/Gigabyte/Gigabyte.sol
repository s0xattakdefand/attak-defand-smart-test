// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GigabyteAttackDefense - Full Attack and Defense Simulation for Gigabyte-Scale Storage in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Gigabyte Data Storage (Vulnerable to Storage and Gas Attacks)
contract InsecureGigabyteStorage {
    mapping(address => bytes) public userData;

    event DataUploaded(address indexed user, uint256 size);

    function uploadData(bytes calldata bigData) external {
        userData[msg.sender] = bigData; // BAD: No size limit, attacker can store GBs
        emit DataUploaded(msg.sender, bigData.length);
    }

    function getData(address user) external view returns (bytes memory) {
        return userData[user];
    }
}

/// @notice Secure Gigabyte Data Storage (Data Size Limits + Cost Model)
contract SecureGigabyteStorage {
    uint256 public constant MAX_UPLOAD_SIZE = 10 * 1024; // 10 KB max per user upload
    uint256 public constant STORAGE_FEE_PER_BYTE = 1e12; // 0.000001 ETH per KB
    mapping(address => bytes32) public userDataHashes;
    mapping(address => uint256) public uploadedSizes;

    event DataHashed(address indexed user, bytes32 hash, uint256 size);

    function uploadData(bytes calldata bigData) external payable {
        require(bigData.length <= MAX_UPLOAD_SIZE, "Data too large");
        uint256 requiredPayment = bigData.length * STORAGE_FEE_PER_BYTE;
        require(msg.value >= requiredPayment, "Insufficient fee");

        bytes32 dataHash = keccak256(bigData);
        userDataHashes[msg.sender] = dataHash;
        uploadedSizes[msg.sender] = bigData.length;

        emit DataHashed(msg.sender, dataHash, bigData.length);
    }

    function getDataHash(address user) external view returns (bytes32) {
        return userDataHashes[user];
    }

    function getUploadedSize(address user) external view returns (uint256) {
        return uploadedSizes[user];
    }
}

/// @notice Attack contract simulating storage grief and gas exhaustion
contract GigabyteIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function floodStorage(bytes calldata hugePayload) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("uploadData(bytes)", hugePayload)
        );
    }
}
