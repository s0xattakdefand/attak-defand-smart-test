// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CNADefenseRouter {
    address public owner;
    mapping(address => bool) public defenders;
    mapping(address => uint256) public callFrequency;
    mapping(address => bool) public blocked;
    bool public paused;

    event CNADetected(address indexed attacker, string category, uint256 count);
    event DefenseActionTriggered(address indexed defender, string action);

    modifier onlyOwnerOrDefender() {
        require(msg.sender == owner || defenders[msg.sender], "Not authorized");
        _;
    }

    modifier notPaused() {
        require(!paused, "System paused due to CNA");
        _;
    }

    constructor() {
        owner = msg.sender;
        defenders[msg.sender] = true;
    }

    function receivePacket(bytes calldata payload) external notPaused {
        callFrequency[msg.sender]++;
        if (callFrequency[msg.sender] > 10) {
            blocked[msg.sender] = true;
            emit CNADetected(msg.sender, "High Frequency CNA", callFrequency[msg.sender]);
        }
    }

    function pauseSystem() external onlyOwnerOrDefender {
        paused = true;
        emit DefenseActionTriggered(msg.sender, "Emergency Pause");
    }

    function unpauseSystem() external onlyOwnerOrDefender {
        paused = false;
        emit DefenseActionTriggered(msg.sender, "Resume");
    }

    function addDefender(address user) external onlyOwnerOrDefender {
        defenders[user] = true;
    }

    function unblockAddress(address attacker) external onlyOwnerOrDefender {
        blocked[attacker] = false;
        callFrequency[attacker] = 0;
    }

    function isBlocked(address user) external view returns (bool) {
        return blocked[user];
    }
}
