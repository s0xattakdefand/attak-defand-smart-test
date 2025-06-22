// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES-CCM Validator — Offchain AES-CCM, onchain commitment verification
contract AESCCMValidator {
    address public admin;

    struct CCMRecord {
        bytes32 commitment; // keccak256(ciphertext || tag || AAD || nonce || keyHash)
        string description;
        bool verified;
    }

    mapping(address => CCMRecord[]) public records;

    event CCMCommitted(address indexed user, uint256 index, bytes32 commitment);
    event CCMVerified(address indexed user, uint256 index);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function commitCCM(
        bytes32 commitment,
        string calldata description
    ) external {
        records[msg.sender].push(CCMRecord(commitment, description, false));
        emit CCMCommitted(msg.sender, records[msg.sender].length - 1, commitment);
    }

    function verifyCCM(
        uint256 index,
        bytes calldata ciphertext,
        bytes16 tag,
        bytes calldata aad,
        bytes12 nonce,
        bytes32 keyHash
    ) external {
        CCMRecord storage record = records[msg.sender][index];
        require(!record.verified, "Already verified");

        bytes32 check = keccak256(abi.encodePacked(ciphertext, tag, aad, nonce, keyHash));
        require(check == record.commitment, "CCM validation failed");

        record.verified = true;
        emit CCMVerified(msg.sender, index);
    }

    function getRecord(address user, uint256 index) external view returns (CCMRecord memory) {
        return records[user][index];
    }
}
