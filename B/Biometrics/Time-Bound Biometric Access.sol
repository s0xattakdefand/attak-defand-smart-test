// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TimeBoundBiometricAccess {
    mapping(address => uint256) public biometricExpiry;
    address public admin;

    event BiometricGranted(address indexed user, uint256 expiry);
    event BiometricRevoked(address indexed user);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    /**
     * @notice Grant time-limited biometric access to a user.
     * @param user The user's address.
     * @param durationInSeconds How long the access should last from now.
     */
    function grantBiometricAccess(address user, uint256 durationInSeconds) public onlyAdmin {
        biometricExpiry[user] = block.timestamp + durationInSeconds;
        emit BiometricGranted(user, biometricExpiry[user]);
    }

    /**
     * @notice Revoke biometric access manually.
     */
    function revokeBiometricAccess(address user) public onlyAdmin {
        biometricExpiry[user] = 0;
        emit BiometricRevoked(user);
    }

    /**
     * @notice Check if a user currently has valid biometric access.
     */
    function hasValidBiometricAccess(address user) public view returns (bool) {
        return block.timestamp < biometricExpiry[user];
    }
}
