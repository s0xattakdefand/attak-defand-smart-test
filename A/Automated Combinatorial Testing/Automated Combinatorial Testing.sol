// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Permission Drift, Combo Bypass, Role XOR
/// Defense Types: Combo Trace, Rule Matrix, Attack Logging

contract ACTCombinatorialTester {
    address public admin;

    struct ComboRule {
        bool roleA;
        bool roleB;
        bool isExpired;
        bool expected; // true = should pass
    }

    ComboRule[] public testCases;
    uint256 public totalTests;
    uint256 public failures;

    event TestResult(uint indexed id, bool result, bool expected);
    event AttackDetected(uint indexed id, string reason);

    constructor() {
        admin = msg.sender;
    }

    /// Add test cases programmatically (normally automated off-chain)
    function addTestCase(bool roleA, bool roleB, bool isExpired, bool expected) external {
        require(msg.sender == admin, "Only admin");
        testCases.push(ComboRule(roleA, roleB, isExpired, expected));
        totalTests++;
    }

    /// Execute all test cases
    function runAllTests() external {
        for (uint i = 0; i < testCases.length; i++) {
            ComboRule memory c = testCases[i];
            bool result = evaluateCombo(c.roleA, c.roleB, c.isExpired);
            emit TestResult(i, result, c.expected);

            if (result != c.expected) {
                failures++;
                emit AttackDetected(i, "Unexpected result in access logic");
            }
        }
    }

    /// Example access logic: roleA AND (roleB OR !isExpired)
    function evaluateCombo(bool roleA, bool roleB, bool isExpired) public pure returns (bool) {
        return roleA && (roleB || !isExpired);
    }

    function getTestCase(uint i) external view returns (ComboRule memory) {
        return testCases[i];
    }

    function getSummary() external view returns (uint total, uint failed) {
        return (totalTests, failures);
    }
}
