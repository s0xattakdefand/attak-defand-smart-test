pragma solidity ^0.8.21;

contract AnomalyBasedIDS {
    mapping(address => uint256) public accessCounter;
    uint256 public constant MAX_ALLOWED_CALLS = 10;

    event AnomalyDetected(address indexed user, uint256 count);

    function monitoredFunction() external {
        accessCounter[msg.sender]++;
        if (accessCounter[msg.sender] > MAX_ALLOWED_CALLS) {
            emit AnomalyDetected(msg.sender, accessCounter[msg.sender]);
            revert("Too many calls detected");
        }
    }
}
