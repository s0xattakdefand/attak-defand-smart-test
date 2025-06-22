// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach:
 * We simulate 'MAC addresses' as unique IDs assigned to each participant. 
 * Possibly ties to a user's address or hashed public key. 
 */
contract MacAddressSim {
    mapping(address => bytes32) public macIDs;

    event MacAssigned(address user, bytes32 macID);

    function assignMAC(bytes32 macID) external {
        require(macIDs[msg.sender] == bytes32(0), "Already assigned");
        macIDs[msg.sender] = macID;
        emit MacAssigned(msg.sender, macID);
    }
}
