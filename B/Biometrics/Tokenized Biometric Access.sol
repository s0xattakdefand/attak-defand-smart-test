// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenizedBiometricAccess {
    mapping(address => bool) public hasNFTAccess;
    address public admin;

    event AccessGranted(address indexed user);
    event AccessRevoked(address indexed user);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    /**
     * @notice Grant biometric token access to a user (simulated by admin).
     * In a real biometric context, the admin would be a biometric backend or oracle.
     */
    function bindBiometricToken(address user) public onlyAdmin {
        hasNFTAccess[user] = true;
        emit AccessGranted(user);
    }

    /**
     * @notice Revoke biometric access.
     */
    function revokeBiometricToken(address user) public onlyAdmin {
        hasNFTAccess[user] = false;
        emit AccessRevoked(user);
    }

    /**
     * @notice Check if an address has biometric token access.
     */
    function isVerified(address user) public view returns (bool) {
        return hasNFTAccess[user];
    }
}
