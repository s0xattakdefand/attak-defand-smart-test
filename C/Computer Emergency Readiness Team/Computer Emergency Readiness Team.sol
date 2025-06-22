// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Web3CERTResponder {
    address public owner;
    mapping(address => bool) public certTeam;
    bool public paused;

    event EmergencyPaused(address indexed by);
    event EmergencyUnpaused(address indexed by);
    event IncidentLogged(address indexed reporter, string category, string details);
    event CERTMemberAdded(address indexed member);
    event CERTMemberRemoved(address indexed member);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyCERT() {
        require(certTeam[msg.sender], "Not CERT");
        _;
    }

    modifier notPaused() {
        require(!paused, "System is paused");
        _;
    }

    constructor() {
        owner = msg.sender;
        certTeam[msg.sender] = true;
    }

    function pauseSystem() external onlyCERT {
        paused = true;
        emit EmergencyPaused(msg.sender);
    }

    function unpauseSystem() external onlyOwner {
        paused = false;
        emit EmergencyUnpaused(msg.sender);
    }

    function logIncident(string calldata category, string calldata details) external onlyCERT {
        emit IncidentLogged(msg.sender, category, details);
    }

    function addCERT(address member) external onlyOwner {
        certTeam[member] = true;
        emit CERTMemberAdded(member);
    }

    function removeCERT(address member) external onlyOwner {
        certTeam[member] = false;
        emit CERTMemberRemoved(member);
    }
}
