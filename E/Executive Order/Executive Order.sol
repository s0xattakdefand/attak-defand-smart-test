// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ExecutiveOrderAttackDefense - Full Attack and Defense Simulation for Executive Order Mechanisms in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Executive Order Contract (Vulnerable to Immediate Overreach)
contract InsecureExecutiveOrder {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function executeOrder(address payable to, uint256 amount) external {
        require(msg.sender == admin, "Only admin");

        // No timelock, no multisig, instant execution
        (bool sent, ) = to.call{value: amount}("");
        require(sent, "Transfer failed");
    }

    receive() external payable {}
}

/// @notice Secure Executive Order Contract (Hardened with Timelock, Nonce, Role-Based Control)
contract SecureExecutiveOrder {
    address public admin;
    uint256 public delayPeriod = 1 days;
    mapping(bytes32 => uint256) public queuedOrders;
    mapping(bytes32 => bool) public executedOrders;

    event OrderQueued(bytes32 indexed orderHash, address indexed target, uint256 amount, uint256 executeAfter);
    event OrderExecuted(bytes32 indexed orderHash, address indexed target, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function queueOrder(address target, uint256 amount, uint256 nonce) external onlyAdmin returns (bytes32 orderHash) {
        require(target != address(0), "Invalid target");

        orderHash = keccak256(abi.encodePacked(target, amount, nonce, address(this), block.chainid));
        require(queuedOrders[orderHash] == 0, "Order already queued");

        queuedOrders[orderHash] = block.timestamp + delayPeriod;

        emit OrderQueued(orderHash, target, amount, block.timestamp + delayPeriod);
    }

    function executeOrder(address payable target, uint256 amount, uint256 nonce) external onlyAdmin {
        bytes32 orderHash = keccak256(abi.encodePacked(target, amount, nonce, address(this), block.chainid));

        uint256 executeAfter = queuedOrders[orderHash];
        require(executeAfter != 0, "Order not queued");
        require(block.timestamp >= executeAfter, "Order still locked");
        require(!executedOrders[orderHash], "Order already executed");

        executedOrders[orderHash] = true;

        (bool sent, ) = target.call{value: amount}("");
        require(sent, "Transfer failed");

        emit OrderExecuted(orderHash, target, amount);
    }

    receive() external payable {}
}

/// @notice Attack contract simulating executive overreach or replay attacks
contract ExecutiveOrderIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackImmediate(address payable victim, uint256 amount) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("executeOrder(address,uint256)", victim, amount)
        );
    }
}
