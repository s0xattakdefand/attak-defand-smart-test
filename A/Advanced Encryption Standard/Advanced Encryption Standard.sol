// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AES Hybrid Commit-Reveal Contract (AES256 Offchain, Verify Onchain)
contract AESCommitReveal {
    address public admin;

    struct AESPayload {
        bytes32 commitment; // keccak256(encryptedData || keyHash)
        bool revealed;
    }

    mapping(address => AESPayload) public payloads;

    event PayloadCommitted(address indexed user, bytes32 commitment);
    event PayloadRevealed(address indexed user, string decryptedData);

    constructor() {
        admin = msg.sender;
    }

    function commitPayload(bytes32 commitment) external {
        require(payloads[msg.sender].commitment == 0, "Already committed");
        payloads[msg.sender] = AESPayload(commitment, false);
        emit PayloadCommitted(msg.sender, commitment);
    }

    /// Reveal AES-decrypted data (decrypted offchain), verified onchain
    function reveal(string calldata decryptedData, bytes32 keyHash) external {
        AESPayload storage p = payloads[msg.sender];
        require(p.commitment != 0, "No commitment found");
        require(!p.revealed, "Already revealed");

        bytes32 check = keccak256(abi.encodePacked(decryptedData, keyHash));
        require(check == p.commitment, "Invalid decryption");

        p.revealed = true;
        emit PayloadRevealed(msg.sender, decryptedData);
    }
}
