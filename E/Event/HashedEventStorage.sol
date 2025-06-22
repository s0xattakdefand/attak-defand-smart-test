// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach:
 * We store only a hash in the event, not the entire data, 
 * reducing log usage and potential spam size.
 */
contract HashedEventStorage {
    event HashedData(address indexed user, bytes32 dataHash);

    function emitHash(bytes32 hashValue) external {
        emit HashedData(msg.sender, hashValue);
    }
}
