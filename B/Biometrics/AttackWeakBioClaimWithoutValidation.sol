// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract InsecureBiometricClaim {
    mapping(address => bool) public hasBiometricAccess;

    // ❌ Any user can claim biometric verification without proof
    function claimBiometricAccess() public {
        hasBiometricAccess[msg.sender] = true;
    }
}
