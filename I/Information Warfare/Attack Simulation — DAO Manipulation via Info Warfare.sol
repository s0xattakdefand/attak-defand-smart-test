// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InfoWarfareDAO {
    mapping(address => uint256) public votes;
    mapping(bytes32 => uint256) public proposals;

    function vote(bytes32 proposalId, uint256 power) external {
        require(power <= votes[msg.sender], "Not enough power");
        proposals[proposalId] += power;
        votes[msg.sender] -= power;
    }

    function airdropVotes(address[] calldata bots, uint256 power) external {
        for (uint256 i = 0; i < bots.length; i++) {
            votes[bots[i]] = power; // 🧨 Info warfare: create fake influence via bots
        }
    }
}
