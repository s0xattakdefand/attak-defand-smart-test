// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ControlAndStatusManager {
    address public owner;

    enum Status { Init, Active, Paused, Finalized }
    Status public currentStatus;

    mapping(address => bool) public admins;
    mapping(address => bool) public operators;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event AdminGranted(address indexed admin);
    event OperatorGranted(address indexed operator);
    event StatusChanged(Status newStatus);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    modifier onlyOperator() {
        require(operators[msg.sender], "Not operator");
        _;
    }

    modifier whenActive() {
        require(currentStatus == Status.Active, "Not active");
        _;
    }

    modifier whenPaused() {
        require(currentStatus == Status.Paused, "Not paused");
        _;
    }

    constructor() {
        owner = msg.sender;
        currentStatus = Status.Init;
    }

    /// 🔧 Control Functions

    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function grantAdmin(address admin) external onlyOwner {
        admins[admin] = true;
        emit AdminGranted(admin);
    }

    function grantOperator(address operator) external onlyAdmin {
        operators[operator] = true;
        emit OperatorGranted(operator);
    }

    function setStatus(Status newStatus) external onlyAdmin {
        currentStatus = newStatus;
        emit StatusChanged(newStatus);
    }

    /// 🚦 Status-Gated Functions

    function runWhenActive() external onlyOperator whenActive returns (string memory) {
        return "Executed in Active mode";
    }

    function emergencyAction() external onlyAdmin whenPaused returns (string memory) {
        return "Executed in Paused mode";
    }
}
