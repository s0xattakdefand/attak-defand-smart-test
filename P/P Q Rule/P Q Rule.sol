// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PQRuleAttackDefense - Attack and Defense Simulation for P → Q Rule Enforcement in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure P → Q handling (Broken Condition Enforcement)
contract InsecurePQ {
    address public owner;
    bool public paid;

    event OwnershipTransferred(address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    function pay() external payable {
        require(msg.value > 0, "No payment sent");
        paid = true;
        emit OwnershipTransferred(msg.sender); // 🔥 Ownership event emitted without real ownership transfer!
    }
}

/// @notice Secure P → Q handling with full atomic enforcement
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePQ is Ownable {
    address public owner;
    bool public paid;

    event PaymentReceived(address indexed payer, uint256 amount);
    event OwnershipTransferred(address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    function payAndClaimOwnership() external payable {
        require(msg.value > 0, "Payment required");
        require(!paid, "Already paid");

        paid = true;
        emit PaymentReceived(msg.sender, msg.value);

        owner = msg.sender;
        emit OwnershipTransferred(msg.sender);
    }

    function getOwner() external view returns (address) {
        return owner;
    }
}

/// @notice Attack contract trying to exploit broken P → Q flow
contract PQIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakePayment() external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("pay()")
        );
    }
}
