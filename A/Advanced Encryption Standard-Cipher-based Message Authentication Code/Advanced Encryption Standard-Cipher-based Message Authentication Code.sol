// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES-CMAC Validation Contract (hybrid offchain-onchain)
contract AESCMACValidator {
    struct CMACRecord {
        bytes32 cmacTag; // offchain AES-CMAC result
        bool validated;
    }

    mapping(address => CMACRecord[]) public validations;

    event CMACSubmitted(address indexed user, uint256 indexed index, bytes32 cmacTag);
    event CMACValidated(address indexed user, uint256 indexed index);

    /// Submit AES-CMAC result (tag)
    function submitCMAC(bytes32 cmacTag) external {
        validations[msg.sender].push(CMACRecord(cmacTag, false));
        emit CMACSubmitted(msg.sender, validations[msg.sender].length - 1, cmacTag);
    }

    /// Validate message + key by matching recomputed simulated tag
    function validateCMAC(
        uint256 index,
        string calldata message,
        bytes32 keyHash // hash of the AES key used offchain
    ) external {
        CMACRecord storage record = validations[msg.sender][index];
        require(!record.validated, "Already validated");

        // Simulate AES-CMAC with keccak(message || key)
        bytes32 computed = keccak256(abi.encodePacked(message, keyHash));
        require(computed == record.cmacTag, "Invalid CMAC");

        record.validated = true;
        emit CMACValidated(msg.sender, index);
    }

    function getCMACRecord(address user, uint256 index) external view returns (CMACRecord memory) {
        return validations[user][index];
    }
}
