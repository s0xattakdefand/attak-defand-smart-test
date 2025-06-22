// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Oracle Drift Attack, Error Amplification Attack, Blind Threshold Attack
/// Defense Types: Bounded Absolute Error, Error Auditing, Tolerance Enforcement

contract AbsoluteErrorValidator {
    address public admin;
    uint256 public maxAllowedError; // e.g., 10 = max 10 units of drift

    event ValueAccepted(address indexed user, uint256 measured, uint256 expected, uint256 absError);
    event ErrorExceeded(address indexed user, uint256 measured, uint256 expected, uint256 absError);
    event AttackDetected(address indexed user, string reason);

    constructor(uint256 _maxAllowedError) {
        admin = msg.sender;
        maxAllowedError = _maxAllowedError;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    /// ADMIN: Set max allowed absolute error tolerance
    function setMaxAllowedError(uint256 newTolerance) external onlyAdmin {
        maxAllowedError = newTolerance;
    }

    /// ATTACK Simulation: Send wrong value just under detection
    function attackNearThreshold(uint256 fakeMeasured, uint256 expected) external returns (uint256) {
        uint256 absErr = _absDiff(fakeMeasured, expected);
        if (absErr <= maxAllowedError) {
            return absErr; // sneaky value accepted
        } else {
            emit AttackDetected(msg.sender, "Drift detected");
            revert("Absolute error too large");
        }
    }

    /// DEFENSE: Validate incoming value with respect to absolute error
    function validateInput(uint256 measured, uint256 expected) external returns (uint256) {
        uint256 absErr = _absDiff(measured, expected);

        if (absErr <= maxAllowedError) {
            emit ValueAccepted(msg.sender, measured, expected, absErr);
        } else {
            emit ErrorExceeded(msg.sender, measured, expected, absErr);
            revert("Absolute error exceeds tolerance");
        }

        return absErr;
    }

    /// Internal: Absolute difference
    function _absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? (a - b) : (b - a);
    }
}
