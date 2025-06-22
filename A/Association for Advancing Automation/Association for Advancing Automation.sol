// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Automation Forgery Attack, Malicious Automation Execution Attack, Automation Drift Attack
/// Defense Types: Automation Registration and Verification, Authorization of Automation Flows, Automation Behavior Auditing

contract AutomationSecurityManager {
    address public admin;

    struct AutomationAgent {
        bool registered;
        string description;
    }

    mapping(address => AutomationAgent) public automationAgents;
    mapping(bytes32 => bool) public authorizedFlows;

    event AgentRegistered(address indexed agent, string description);
    event FlowAuthorized(bytes32 indexed flowId);
    event AutomationExecuted(address indexed agent, bytes32 flowId);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    modifier onlyAutomationAgent() {
        if (!automationAgents[msg.sender].registered) {
            emit AttackDetected(msg.sender, "Unregistered automation agent attempt");
            revert("Automation agent not registered");
        }
        _;
    }

    /// ATTACK Simulation: Automation agent forgery
    function attackFakeAutomation(bytes32 flowId) external {
        emit AutomationExecuted(msg.sender, flowId); // simulates unauthorized bot operating
    }

    /// DEFENSE: Register a trusted automation agent
    function registerAutomationAgent(address agent, string calldata description) external onlyAdmin {
        automationAgents[agent] = AutomationAgent({
            registered: true,
            description: description
        });

        emit AgentRegistered(agent, description);
    }

    /// DEFENSE: Admin authorizes specific flows (operations)
    function authorizeAutomationFlow(bytes32 flowId) external onlyAdmin {
        authorizedFlows[flowId] = true;
        emit FlowAuthorized(flowId);
    }

    /// DEFENSE: Secure automation operation execution
    function executeAutomation(bytes32 flowId) external onlyAutomationAgent {
        require(authorizedFlows[flowId], "Flow not authorized");

        emit AutomationExecuted(msg.sender, flowId);
    }

    /// View automation agent details
    function viewAutomationAgent(address agent) external view returns (bool registered, string memory description) {
        AutomationAgent memory a = automationAgents[agent];
        return (a.registered, a.description);
    }

    /// View flow authorization status
    function isFlowAuthorized(bytes32 flowId) external view returns (bool) {
        return authorizedFlows[flowId];
    }
}
