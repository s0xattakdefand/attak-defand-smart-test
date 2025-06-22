pragma solidity ^0.8.21;

contract HeartbeatJitterDetector {
    mapping(address => uint256) public lastPing;
    uint256 public allowedDelay = 120; // 2 mins max jitter

    function ping() external {
        lastPing[msg.sender] = block.timestamp;
    }

    function isLive(address node) external view returns (bool) {
        return block.timestamp - lastPing[node] <= allowedDelay;
    }
}
