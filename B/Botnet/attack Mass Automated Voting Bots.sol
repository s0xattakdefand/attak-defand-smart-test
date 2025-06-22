// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MaliciousBotnetVoting {
    mapping(address => bool) public hasVoted;
    uint256 public votes;

    event Voted(address bot);

    function vote() public {
        require(!hasVoted[msg.sender], "Already voted");
        hasVoted[msg.sender] = true;
        votes += 1;

        emit Voted(msg.sender);
    }
}
