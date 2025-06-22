// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ⚠️ Fake "encryption" logic – misleading and insecure!
contract FakeAES {
    mapping(address => bytes32) public encryptedSecrets;

    function storeEncrypted(bytes32 fakeAES) public {
        // Attacker might provide plaintext XORed with a known key
        encryptedSecrets[msg.sender] = fakeAES;
    }

    function getEncrypted() public view returns (bytes32) {
        return encryptedSecrets[msg.sender];
    }
}
