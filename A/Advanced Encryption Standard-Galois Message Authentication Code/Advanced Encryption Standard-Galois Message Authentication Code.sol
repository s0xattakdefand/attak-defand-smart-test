// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES-GMAC Validator — Offchain MAC, Onchain Verification
contract AESGMACValidator {
    struct GMACRecord {
        bytes32 tagCommitment;
        bool validated;
        string context; // Description or AAD metadata
    }

    mapping(address => GMACRecord[]) public validations;

    event GMACCommitted(address indexed user, uint256 index, bytes32 commitment);
    event GMACValidated(address indexed user, uint256 index);

    /// Commit AES-GMAC tag hash (offchain tag, nonce, keyHash)
    function commitGMAC(bytes32 tagCommitment, string calldata context) external {
        validations[msg.sender].push(GMACRecord(tagCommitment, false, context));
        emit GMACCommitted(msg.sender, validations[msg.sender].length - 1, tagCommitment);
    }

    /// Reveal and validate the tag
    function validateGMAC(
        uint256 index,
        bytes16 tag,
        bytes12 nonce,
        bytes32 keyHash
    ) external {
        GMACRecord storage record = validations[msg.sender][index];
        require(!record.validated, "Already validated");

        bytes32 computed = keccak256(abi.encodePacked(tag, nonce, keyHash));
        require(computed == record.tagCommitment, "Invalid GMAC tag");

        record.validated = true;
        emit GMACValidated(msg.sender, index);
    }

    function getRecord(address user, uint256 index) external view returns (GMACRecord memory) {
        return validations[user][index];
    }
}
