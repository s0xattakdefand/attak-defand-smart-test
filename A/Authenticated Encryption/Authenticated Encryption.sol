// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AuthenticatedEncryptionVerifier — Verify AE ciphertext integrity via onchain hash
contract AuthenticatedEncryptionVerifier {
    address public admin;

    struct AERecord {
        bytes32 commitment; // keccak256(ciphertext || tag || AAD || nonce || keyHash)
        bool verified;
        string note;
    }

    mapping(address => AERecord[]) public records;

    event AECommitted(address indexed user, uint256 index, bytes32 commitment);
    event AEVerified(address indexed user, uint256 index);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function commitAE(bytes32 commitment, string calldata note) external {
        records[msg.sender].push(AERecord(commitment, false, note));
        emit AECommitted(msg.sender, records[msg.sender].length - 1, commitment);
    }

    function verifyAE(
        uint256 index,
        bytes calldata ciphertext,
        bytes16 tag,
        bytes calldata aad,
        bytes12 nonce,
        bytes32 keyHash
    ) external {
        AERecord storage record = records[msg.sender][index];
        require(!record.verified, "Already verified");

        bytes32 expected = keccak256(abi.encodePacked(ciphertext, tag, aad, nonce, keyHash));
        require(expected == record.commitment, "AE verification failed");

        record.verified = true;
        emit AEVerified(msg.sender, index);
    }

    function getRecord(address user, uint256 index) external view returns (AERecord memory) {
        return records[user][index];
    }
}
