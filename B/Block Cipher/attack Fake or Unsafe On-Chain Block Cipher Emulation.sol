// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InsecureBlockCipherSim {
    mapping(address => bytes32) public encryptedMessage;

    function encryptAndStore(bytes32 plaintext) public {
        // ❌ This is NOT encryption — just hashing!
        encryptedMessage[msg.sender] = keccak256(abi.encodePacked(plaintext));
    }

    function getEncrypted() public view returns (bytes32) {
        return encryptedMessage[msg.sender];
    }
}
