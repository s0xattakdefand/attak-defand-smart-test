pragma solidity ^0.8.21;

contract IPReputation {
    address public admin;

    mapping(string => uint256) public ipScore;

    constructor() {
        admin = msg.sender;
    }

    function reportIP(string memory ip, uint256 penalty) external {
        ipScore[ip] -= penalty;
    }

    function rewardIP(string memory ip, uint256 score) external {
        ipScore[ip] += score;
    }

    function accessWithReputation(string memory ip) external view returns (bool) {
        return ipScore[ip] >= 100;
    }
}
