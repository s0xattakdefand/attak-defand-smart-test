// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract CallAdmissionManager is AccessControl, ReentrancyGuard {
    bytes32 public constant CALLER_ROLE = keccak256("CALLER_ROLE");

    // Concurrency lock
    bool private inCall;

    // Rate limiting
    uint256 public blockCap = 5;
    uint256 public callsThisBlock;
    uint256 public lastBlock;

    // Token gating
    mapping(address => uint256) public tokens;

    event ActionExecuted(address indexed user);

    constructor(address admin) {
        // Use `_grantRole` in modern OpenZeppelin AccessControl
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    // Admin can deposit tokens to a user
    function depositTokens(address user, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        tokens[user] += amount;
    }

    function setBlockCap(uint256 cap) external onlyRole(DEFAULT_ADMIN_ROLE) {
        blockCap = cap;
    }

    // --- Modifiers for call admission ---

    modifier concurrencyLock() {
        require(!inCall, "[CAC] Another call is active");
        inCall = true;
        _;
        inCall = false;
    }

    modifier blockLimit() {
        if (block.number != lastBlock) {
            lastBlock = block.number;
            callsThisBlock = 0;
        }
        require(callsThisBlock < blockCap, "[CAC] Block cap reached");
        callsThisBlock++;
        _;
    }

    modifier tokenGate() {
        require(tokens[msg.sender] > 0, "[CAC] No tokens available");
        tokens[msg.sender]--;
        _;
    }

    modifier onlyAdmittedRole() {
        require(hasRole(CALLER_ROLE, msg.sender), "[CAC] Not whitelisted");
        _;
    }

    // Example function that uses all forms of admission
    function admittedActionAll() 
        external 
        concurrencyLock 
        blockLimit 
        tokenGate 
        onlyAdmittedRole 
        nonReentrant 
    {
        // The actual logic
        emit ActionExecuted(msg.sender);
    }
}
