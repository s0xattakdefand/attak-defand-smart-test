// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PiggybackingSecure {
    address public owner;
    mapping(address => uint256) public balances;

    event Acknowledgment(address indexed user, string message);
    event OwnerChanged(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Unauthorized");
        _;
    }

    // Secure: Pure acknowledgment function, no side effects
    function acknowledge(address user, string calldata message) public {
        emit Acknowledgment(user, message);
    }

    // Secure: Separated administrative action with strict access control
    function changeOwner(address newOwner) public onlyOwner {
        address oldOwner = owner;
        owner = newOwner;
        emit OwnerChanged(oldOwner, newOwner);
    }
}
