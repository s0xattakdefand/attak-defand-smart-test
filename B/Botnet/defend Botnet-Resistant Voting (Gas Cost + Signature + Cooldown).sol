// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract AntiBotnetVoting {
    using ECDSA for bytes32;

    address public admin;
    mapping(address => bool) public hasVoted;
    mapping(address => uint256) public lastVoteTime;

    uint256 public votes;
    uint256 public cooldown = 60; // 60 seconds

    event VoteCast(address indexed user);

    constructor(address _admin) {
        admin = _admin;
    }

    function vote(uint256 nonce, bytes calldata sig) public {
        require(!hasVoted[msg.sender], "Already voted");
        require(block.timestamp > lastVoteTime[msg.sender] + cooldown, "Cooldown active");

        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce));
        bytes32 signedHash = hash.toEthSignedMessageHash();
        require(signedHash.recover(sig) == admin, "Invalid signature");

        hasVoted[msg.sender] = true;
        lastVoteTime[msg.sender] = block.timestamp;
        votes++;

        emit VoteCast(msg.sender);
    }
}
