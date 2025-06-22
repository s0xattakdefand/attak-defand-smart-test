// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Fake or worthless certificate acceptance.
 * No actual CA check or signature validation.
 */
contract FakeCertAuth {
    mapping(address => bytes) public userCerts;

    function storeCertificate(bytes calldata certData) external {
        // ❌ Just store it, no validation of CA, no signature checks
        userCerts[msg.sender] = certData;
    }

    function isAuthenticated(address user) external view returns (bool) {
        // ❌ Blindly trusts existence of certificate
        return userCerts[user].length > 0;
    }
}
