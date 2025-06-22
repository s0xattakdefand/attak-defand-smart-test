// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract BlueTeamDefense is ReentrancyGuard, AccessControl {
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");
    mapping(address => bool) public flaggedUsers;
    event Alert(address indexed source, string reason);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    modifier onlyAnalyst() {
        require(hasRole(ANALYST_ROLE, msg.sender), "Not an analyst");
        _;
    }

    modifier notFlagged() {
        require(!flaggedUsers[msg.sender], "Address is flagged");
        _;
    }

    function flagAddress(address user, string calldata reason) public onlyAnalyst {
        flaggedUsers[user] = true;
        emit Alert(user, reason);
    }

    function unflagAddress(address user) public onlyAnalyst {
        flaggedUsers[user] = false;
    }

    function secureWithdraw(address payable to, uint256 amount) public nonReentrant notFlagged {
        require(to != address(0), "Invalid recipient");
        require(amount <= address(this).balance, "Insufficient funds");
        to.transfer(amount);
    }

    receive() external payable {}
}
