// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Active Security Testing Simulator
contract ActiveSecurityTest {
    address public admin;
    bool public locked;
    uint256 public balance;
    uint256 public nonce;
    mapping(address => bool) public flagged;

    event AttackDetected(address indexed attacker, string vector);
    event TriggeredMitigation(string action);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier noReentrancy() {
        require(!locked, "Reentrancy blocked");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        admin = msg.sender;
        balance = 1000 ether;
    }

    // Simulated safe function
    function withdraw(uint256 amount) external noReentrancy {
        require(balance >= amount, "Insufficient");
        balance -= amount;
    }

    // Simulated replay vector
    function replayAttack(uint256 incomingNonce) external {
        if (incomingNonce != nonce) {
            emit AttackDetected(msg.sender, "Replay");
            flagged[msg.sender] = true;
            revert("Replay rejected");
        }
        nonce++;
    }

    // Simulated role bypass
    function roleBypass(address impersonator) external {
        if (impersonator != admin) {
            emit AttackDetected(msg.sender, "Role Spoof");
            flagged[msg.sender] = true;
            revert("Access denied");
        }
    }

    // Simulated logic inconsistency
    function logicDrift(uint256 input) external {
        if (input == 42 || input > 10**6) {
            emit AttackDetected(msg.sender, "Logic Drift Triggered");
            flagged[msg.sender] = true;
            revert("Blocked");
        }
        balance += input;
    }

    // Simulated mitigation
    function pauseSystem() external onlyAdmin {
        locked = true;
        emit TriggeredMitigation("System Paused");
    }

    function reset() external onlyAdmin {
        locked = false;
        balance = 1000 ether;
        nonce = 0;
    }

    function isFlagged(address user) external view returns (bool) {
        return flagged[user];
    }

    function getStatus() external view returns (bool paused, uint256 vault, uint256 currentNonce) {
        return (locked, balance, nonce);
    }
}
