// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach to password escrow:
 * The password is stored off-chain, but the contract references an encryption 
 * so that if the user wants to reveal, they do so in an event or partial code. 
 * Not a direct on-chain password check, but more like a reference approach.
 */
contract OffChainEscrowPasswordReference {
    bytes32 public hashedKey;
    bool public isReleased;

    constructor(bytes32 _hashedKey) payable {
        hashedKey = _hashedKey;
        isReleased = false;
    }

    function revealKey(string calldata plaintext, bytes32 salt) external {
        require(!isReleased, "Already done");
        require(keccak256(abi.encodePacked(plaintext, salt)) == hashedKey, "Invalid key");
        isReleased = true;
        // transfer escrow to designated party
    }
}
