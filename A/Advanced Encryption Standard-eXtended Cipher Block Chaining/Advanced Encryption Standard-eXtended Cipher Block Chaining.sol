// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES-XCBC Validator — Offchain AES-MAC, onchain validation
contract AESXCBCValidator {
    struct XCBCPayload {
        bytes32 xcbcTagCommit; // hash of tag || keyHash
        bool validated;
        string associatedData;
    }

    mapping(address => XCBCPayload[]) public validations;

    event TagCommitted(address indexed user, uint256 indexed index, bytes32 xcbcTagCommit);
    event TagValidated(address indexed user, uint256 indexed index, string data);

    /// Submit AES-XCBC hash commitment (offchain generated)
    function commitTag(bytes32 xcbcTagCommit, string calldata associatedData) external {
        validations[msg.sender].push(XCBCPayload(xcbcTagCommit, false, associatedData));
        emit TagCommitted(msg.sender, validations[msg.sender].length - 1, xcbcTagCommit);
    }

    /// Validate tag from decrypted message and AES key hash
    function validateTag(uint256 index, bytes16 xcbcTag, bytes32 keyHash) external {
        XCBCPayload storage payload = validations[msg.sender][index];
        require(!payload.validated, "Already validated");

        bytes32 recomputed = keccak256(abi.encodePacked(xcbcTag, keyHash));
        require(recomputed == payload.xcbcTagCommit, "Invalid tag");

        payload.validated = true;
        emit TagValidated(msg.sender, index, payload.associatedData);
    }

    function getValidation(address user, uint256 index) external view returns (XCBCPayload memory) {
        return validations[user][index];
    }
}
