// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: 
 * We store just a pointer (like IPFS hash) to an off-chain encrypted file.
 */
contract OffChainEncryptedPointer {
    string public ipfsHash; // e.g. IPFS address of an encrypted file

    constructor(string memory _ipfsHash) {
        ipfsHash = _ipfsHash;
    }
}
