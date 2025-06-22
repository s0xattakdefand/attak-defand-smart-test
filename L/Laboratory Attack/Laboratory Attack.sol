// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LaboratoryAttackDefense - Full Attack and Defense Simulation for Laboratory Attacks in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Laboratory Deployment (No Environment Tagging, No Restrictions)
contract InsecureLaboratory {
    mapping(address => uint256) public experimentalBalances;

    event LabDeposit(address indexed user, uint256 amount);

    function depositLabFunds() external payable {
        // BAD: No environment restrictions
        experimentalBalances[msg.sender] += msg.value;
        emit LabDeposit(msg.sender, msg.value);
    }

    function withdrawLabFunds(uint256 amount) external {
        require(experimentalBalances[msg.sender] >= amount, "Insufficient lab balance");
        experimentalBalances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

/// @notice Secure Laboratory Deployment (Environment Tagging + Expiry + Access Control)
contract SecureLaboratory {
    address public immutable owner;
    string public constant ENVIRONMENT = "LAB";
    uint256 public immutable labCreationTime;
    uint256 public constant LAB_LIFESPAN = 7 days;
    mapping(address => uint256) public labBalances;

    event LabDeposit(address indexed user, uint256 amount);
    event LabFundsExpired(address indexed user, uint256 remainingAmount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier labActive() {
        require(block.timestamp <= labCreationTime + LAB_LIFESPAN, "Lab expired");
        _;
    }

    constructor() {
        owner = msg.sender;
        labCreationTime = block.timestamp;
    }

    function depositLabFunds() external payable labActive {
        require(msg.value > 0, "Zero deposit");
        labBalances[msg.sender] += msg.value;
        emit LabDeposit(msg.sender, msg.value);
    }

    function withdrawLabFunds(uint256 amount) external labActive {
        require(labBalances[msg.sender] >= amount, "Insufficient lab balance");
        labBalances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    function expireLabFunds(address user) external onlyOwner {
        require(block.timestamp > labCreationTime + LAB_LIFESPAN, "Lab still active");
        uint256 remaining = labBalances[user];
        labBalances[user] = 0;
        payable(owner).transfer(remaining);
        emit LabFundsExpired(user, remaining);
    }

    function getEnvironment() external pure returns (string memory) {
        return ENVIRONMENT;
    }
}

/// @notice Attack contract simulating lab drift into production
contract LaboratoryIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function interactAsIfProduction() external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("depositLabFunds()")
        );
    }
}
