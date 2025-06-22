// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureRelayWithTTL {
    struct RelayMsg {
        string content;
        uint256 ttl;
    }

    mapping(bytes32 => bool) public processed;

    event Forwarded(address indexed from, string msg);

    function forward(RelayMsg calldata message) external {
        require(message.ttl > block.number, "Message expired");

        bytes32 id = keccak256(abi.encodePacked(msg.sender, message.content, message.ttl));
        require(!processed[id], "Already relayed");

        processed[id] = true;
        emit Forwarded(msg.sender, message.content);
    }
}
