// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LabelAttackDefense - Full Attack and Defense Simulation for Label Mechanisms in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Label System (Anyone Can Assign or Modify Labels Freely)
contract InsecureLabelSystem {
    mapping(address => string) public labels;

    event LabelAssigned(address indexed user, string label);

    function assignLabel(address user, string calldata label) external {
        // BAD: No control over who can assign or modify labels
        labels[user] = label;
        emit LabelAssigned(user, label);
    }

    function hasLabel(address user, string calldata label) external view returns (bool) {
        return keccak256(bytes(labels[user])) == keccak256(bytes(label));
    }
}

/// @notice Secure Label System (Authorization + Immutable Assignment + Rate Limiting)
contract SecureLabelSystem {
    address public immutable owner;
    mapping(address => bytes32) public labels;
    mapping(address => uint256) public labelAssignmentTimestamps;
    mapping(bytes32 => bool) public validLabels;
    uint256 public constant ASSIGNMENT_COOLDOWN = 10 minutes;

    event LabelAssigned(address indexed user, bytes32 indexed label);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        validLabels[keccak256("admin")] = true;
        validLabels[keccak256("user")] = true;
        validLabels[keccak256("governor")] = true;
    }

    function assignLabel(address user, string calldata label) external onlyOwner {
        bytes32 labelHash = keccak256(bytes(label));
        require(validLabels[labelHash], "Invalid label");
        require(labels[user] == bytes32(0), "Label already assigned");
        require(block.timestamp >= labelAssignmentTimestamps[user] + ASSIGNMENT_COOLDOWN, "Cooldown active");

        labels[user] = labelHash;
        labelAssignmentTimestamps[user] = block.timestamp;

        emit LabelAssigned(user, labelHash);
    }

    function hasLabel(address user, string calldata label) external view returns (bool) {
        return labels[user] == keccak256(bytes(label));
    }
}

/// @notice Attack contract simulating label overwrite or forgery
contract LabelIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function overwriteLabel(address victim, string calldata fakeLabel) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("assignLabel(address,string)", victim, fakeLabel)
        );
    }
}
