// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DEFENSE TYPE:
 * A safe echo contract that requires a small fee or has rate limits,
 * preventing spam or indefinite data echo attacks.
 */
contract RateLimitedEchoReply {
    event Echoed(address indexed sender, string data);

    mapping(address => uint256) public lastEchoTime;
    uint256 public echoFee = 0.001 ether;       // a small fee for each echo
    uint256 public minInterval = 60;           // 1 minute cooldown

    function setEchoFee(uint256 fee) external {
        // For demonstration, we assume an owner check or AccessControl
        echoFee = fee;
    }

    function setMinInterval(uint256 interval) external {
        // Similarly assume onlyOwner for production
        minInterval = interval;
    }

    function echo(string calldata message) external payable {
        // 1) Must pay a small fee to call echo
        require(msg.value >= echoFee, "Insufficient echo fee");

        // 2) Rate limit to once per 'minInterval'
        require(block.timestamp >= lastEchoTime[msg.sender] + minInterval, "Wait for cooldown");

        lastEchoTime[msg.sender] = block.timestamp;
        emit Echoed(msg.sender, message);
    }
}
