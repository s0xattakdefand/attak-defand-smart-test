// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Another approach: use a random ID from VRF or a secure random source 
 * to assign ephemeral ports => less guessable or trackable.
 */
contract VRFEphemeral {
    address public admin;
    // hypothetical VRF result
    mapping(address => uint256) public ephemeralID;

    constructor() {
        admin = msg.sender;
    }

    function setUserEphemeral(address user, uint256 randomID) external {
        require(msg.sender == admin, "Not admin");
        ephemeralID[user] = randomID;
    }
}
