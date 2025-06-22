// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES-CTR Validator (offchain encryption, onchain hash verification)
contract AESCTRValidator {
    struct CTRPayload {
        bytes32 commitment; // keccak256(ciphertext || keyHash || nonce)
        bool validated;
        string decrypted;
    }

    mapping(address => CTRPayload[]) public records;

    event CTRCommitted(address indexed user, uint256 index, bytes32 commitment);
    event CTRValidated(address indexed user, uint256 index, string plaintext);

    function commitCTR(bytes32 commitment) external {
        records[msg.sender].push(CTRPayload(commitment, false, ""));
        emit CTRCommitted(msg.sender, records[msg.sender].length - 1, commitment);
    }

    function validateCTR(
        uint256 index,
        bytes calldata ciphertext,
        bytes32 keyHash,
        bytes12 nonce,
        string calldata decrypted
    ) external {
        CTRPayload storage record = records[msg.sender][index];
        require(!record.validated, "Already validated");

        bytes32 check = keccak256(abi.encodePacked(ciphertext, keyHash, nonce));
        require(check == record.commitment, "CTR validation failed");

        record.validated = true;
        record.decrypted = decrypted;
        emit CTRValidated(msg.sender, index, decrypted);
    }

    function getRecord(address user, uint256 index) external view returns (CTRPayload memory) {
        return records[user][index];
    }
}
