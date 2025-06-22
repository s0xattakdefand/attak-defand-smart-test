// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// ACT Simulation Contract — Fuzzing drift-based selector targeting
contract ACTSimulator {
    address public target;
    mapping(address => uint256) public driftScore;
    bool public defenseEnabled;

    event AttackAttempt(address indexed attacker, bytes4 selector, uint256 score);
    event AttackDetected(address attacker, string reason);
    event DefenseTriggered();

    constructor(address _target) {
        target = _target;
        defenseEnabled = true;
    }

    /// Drift attack with mutated selector
    function attack(bytes calldata payload) external {
        bytes4 selector;
        assembly {
            selector := calldataload(payload.offset)
        }

        // Drift scoring heuristic
        driftScore[msg.sender] += uint256(uint32(selector)) % 97;

        emit AttackAttempt(msg.sender, selector, driftScore[msg.sender]);

        // Detection trigger
        if (driftScore[msg.sender] > 200 && defenseEnabled) {
            emit AttackDetected(msg.sender, "Entropy threshold exceeded");
            revert("ACT: Blocked by detection system");
        }

        // Try forwarding (attack path)
        (bool success, ) = target.call(payload);
        require(success, "ACT: Attack failed");
    }

    function toggleDefense(bool state) external {
        require(msg.sender == tx.origin, "EOA only");
        defenseEnabled = state;
        emit DefenseTriggered();
    }
}
