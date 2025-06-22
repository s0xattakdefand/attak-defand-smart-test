// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RateLimitedEchoReply {
    event Echoed(address indexed sender, string data);

    mapping(address => uint256) public lastEcho;
    uint256 public echoFee = 0.001 ether;
    uint256 public minInterval = 60;

    function setEchoFee(uint256 fee) external {
        echoFee = fee;
    }

    function setMinInterval(uint256 interval) external {
        minInterval = interval;
    }

    function echo(string calldata message) external payable {
        require(msg.value >= echoFee, "Insufficient fee");
        require(block.timestamp >= lastEcho[msg.sender] + minInterval, "Wait for cooldown");

        lastEcho[msg.sender] = block.timestamp;
        emit Echoed(msg.sender, message);
    }
}
