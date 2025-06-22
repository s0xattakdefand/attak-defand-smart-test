// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZeroFillDefense — Demonstrates and defends against Zero Fill-based exploits

contract ZeroFillDefense {
    address public owner;
    mapping(address => uint256) public accessLevel;
    mapping(address => bool) public whitelist;

    event AccessGranted(address indexed user, uint256 level);
    event Whitelisted(address indexed user);
    event LogicExecuted(address indexed by, uint256 result);

    constructor() {
        owner = msg.sender;
        whitelist[owner] = true;
        accessLevel[owner] = 100;
    }

    /// ❌ Vulnerable: assumes any address with level > 0 is valid
    function vulnerableAccess(address user) external view returns (string memory) {
        if (accessLevel[user] > 0) {
            return "Granted";
        }
        return "Denied";
    }

    /// ✅ Fixed: explicitly deny if access level was never granted
    function secureAccess(address user) external view returns (string memory) {
        if (accessLevel[user] != 0 && whitelist[user]) {
            return "Granted";
        }
        return "Denied";
    }

    /// ❌ Vulnerable: anyone can call with address(0)
    function setOwner(address newOwner) external {
        require(newOwner != address(0), "Zero address");
        require(msg.sender == owner, "Not owner");
        owner = newOwner;
    }

    /// ✅ Secure assignment with zero guard
    function setAccess(address user, uint256 level) external {
        require(msg.sender == owner, "Only owner");
        require(user != address(0), "Invalid address");
        require(level > 0, "Level must be non-zero");

        whitelist[user] = true;
        accessLevel[user] = level;

        emit AccessGranted(user, level);
        emit Whitelisted(user);
    }

    /// ✅ Defensive logic using zero-check
    function executeLogic(uint256 input) external returns (uint256) {
        require(input != 0, "Zero input rejected");

        uint256 result = input * 2;
        emit LogicExecuted(msg.sender, result);
        return result;
    }
}
