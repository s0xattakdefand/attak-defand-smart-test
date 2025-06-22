// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ControlledRateSetter is AccessControl {
    using ECDSA for bytes32;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 public currentRate;
    uint256 public lastUpdated;
    address public trustedOracle;

    event RateChanged(uint256 oldRate, uint256 newRate);
    event OracleOverride(uint256 newRate, address by);

    constructor(uint256 initialRate, address oracle) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        currentRate = initialRate;
        trustedOracle = oracle;
        lastUpdated = block.timestamp;
    }

    modifier rateLimit(uint256 newRate) {
        require(block.timestamp >= lastUpdated + 1 hours, "Rate update cooldown");
        uint256 maxDelta = currentRate / 10; // max 10% change
        uint256 delta = newRate > currentRate ? newRate - currentRate : currentRate - newRate;
        require(delta <= maxDelta, "Rate change too large");
        _;
    }

    function updateRate(uint256 newRate) external onlyRole(ADMIN_ROLE) rateLimit(newRate) {
        uint256 oldRate = currentRate;
        currentRate = newRate;
        lastUpdated = block.timestamp;
        emit RateChanged(oldRate, newRate);
    }

    function emergencyOverride(uint256 newRate, bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encodePacked(newRate, address(this))).toEthSignedMessageHash();
        require(digest.recover(sig) == trustedOracle, "Invalid oracle signature");

        currentRate = newRate;
        lastUpdated = block.timestamp;
        emit OracleOverride(newRate, msg.sender);
    }
}
