// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AESVerifier {
    address public owner;
    mapping(address => bytes32) private aesHashes;

    event AESHashStored(address indexed user, bytes32 hash);
    event AESHashVerified(address indexed user);

    constructor() {
        owner = msg.sender;
    }

    function storeAESHash(bytes32 aesHash) public {
        aesHashes[msg.sender] = aesHash;
        emit AESHashStored(msg.sender, aesHash);
    }

    function verifyAES(bytes32 inputDecrypted) public view returns (bool) {
        return keccak256(abi.encodePacked(inputDecrypted)) == aesHashes[msg.sender];
    }

    function getMyAESHash() public view returns (bytes32) {
        return aesHashes[msg.sender];
    }
}
