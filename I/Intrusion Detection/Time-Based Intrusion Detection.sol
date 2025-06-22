pragma solidity ^0.8.21;

contract TimeBasedIDS {
    mapping(address => uint256) public lastAccessTime;
    uint256 public constant TIME_DELAY = 1 minutes;

    event RapidAccessDetected(address user, uint256 lastTime);

    function timeSensitiveAction() external {
        uint256 lastTime = lastAccessTime[msg.sender];
        if (block.timestamp < lastTime + TIME_DELAY) {
            emit RapidAccessDetected(msg.sender, lastTime);
            revert("Access too soon");
        }
        lastAccessTime[msg.sender] = block.timestamp;
    }
}
