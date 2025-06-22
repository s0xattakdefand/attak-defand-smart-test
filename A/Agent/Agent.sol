// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AgentRegistry — Tracks agent-to-owner delegation and behavior
contract AgentRegistry {
    address public admin;

    struct Agent {
        address owner;
        string role;         // e.g. "vote-relayer", "vault-bot"
        bool active;
        uint256 createdAt;
    }

    mapping(address => Agent) public agents;
    mapping(address => bool) public approvedOwners;

    event AgentRegistered(address indexed agent, address indexed owner, string role);
    event AgentDisabled(address indexed agent);
    event AgentAction(address indexed agent, string actionType, string details);

    modifier onlyOwner() {
        require(approvedOwners[msg.sender], "Not an approved owner");
        _;
    }

    modifier onlyAgent() {
        require(agents[msg.sender].active, "Inactive or unregistered agent");
        _;
    }

    constructor() {
        admin = msg.sender;
        approvedOwners[msg.sender] = true;
    }

    function registerAgent(address agent, string calldata role) external onlyOwner {
        agents[agent] = Agent(msg.sender, role, true, block.timestamp);
        emit AgentRegistered(agent, msg.sender, role);
    }

    function disableAgent(address agent) external {
        require(msg.sender == agents[agent].owner || msg.sender == admin, "Unauthorized");
        agents[agent].active = false;
        emit AgentDisabled(agent);
    }

    function performAgentAction(string calldata actionType, string calldata details) external onlyAgent {
        emit AgentAction(msg.sender, actionType, details);
    }

    function isAgentActive(address agent) external view returns (bool) {
        return agents[agent].active;
    }

    function getAgent(address agent) external view returns (Agent memory) {
        return agents[agent];
    }

    function approveOwner(address user) external {
        require(msg.sender == admin, "Admin only");
        approvedOwners[user] = true;
    }
}
