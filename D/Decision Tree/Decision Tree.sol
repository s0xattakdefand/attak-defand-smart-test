// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DecisionTreeAttackDefense - Full Attack and Defense Simulation for Decision Tree Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Decision Tree Contract (Vulnerable to Decision Drift and Logic Injection)
contract InsecureDecisionTree {
    function makeDecision(uint256 input) external pure returns (string memory result) {
        if (input < 10) {
            result = "Small Value";
        } else if (input < 100) {
            result = "Medium Value";
        } else if (input < 1000) {
            result = "Large Value";
        } // No fallback else, unhandled > 1000!
    }
}

/// @notice Secure Decision Tree Contract (Fully Hardened and Gas Bounded)
contract SecureDecisionTree {
    address public owner;
    uint256 public gasTraversalLimit = 5; // max depth
    bool public lockedTree;

    struct Node {
        uint256 minValue;
        uint256 maxValue;
        string label;
    }

    Node[] public decisionNodes;

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier treeUnlocked() {
        require(!lockedTree, "Tree locked");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addDecisionNode(uint256 minValue, uint256 maxValue, string calldata label) external onlyOwner treeUnlocked {
        require(minValue < maxValue, "Invalid node range");
        require(bytes(label).length > 0, "Empty label");
        decisionNodes.push(Node({minValue: minValue, maxValue: maxValue, label: label}));
    }

    function lockTree() external onlyOwner {
        lockedTree = true;
    }

    function classifyInput(uint256 input) external view returns (string memory result) {
        uint256 traversed = 0;
        for (uint256 i = 0; i < decisionNodes.length; i++) {
            Node memory node = decisionNodes[i];
            if (input >= node.minValue && input < node.maxValue) {
                return node.label;
            }
            traversed++;
            require(traversed <= gasTraversalLimit, "Exceeded traversal depth");
        }
        revert("Input out of range");
    }

    function getNode(uint256 index) external view returns (Node memory) {
        require(index < decisionNodes.length, "Invalid node index");
        return decisionNodes[index];
    }
}

/// @notice Attack contract simulating decision tree drift attacks
contract DecisionTreeIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function sendExtremeInput(uint256 input) external returns (bool success, bytes memory result) {
        (success, result) = targetInsecure.call(
            abi.encodeWithSignature("makeDecision(uint256)", input)
        );
    }
}
