// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title EIP712PKI
 * Demonstrates storing a certificate after verifying via an off-chain PKI using EIP-712 domain separation.
 */
contract EIP712PKI {
    using ECDSA for bytes32;

    address public trustedCA;

    struct Certificate {
        bytes32 certHash;
        uint256 expiry;
    }

    mapping(address => Certificate) public userCerts;

    event CertStored(address indexed user, bytes32 indexed certHash, uint256 expiry);

    constructor(address ca) {
        trustedCA = ca;
    }

    // Example function: store the certificate after verifying CA signature with EIP-712
    function storeCertificateEIP712(
        bytes32 certHash,
        uint256 expiry,
        bytes calldata typedSig
    ) external {
        require(expiry > block.timestamp, "Cert already expired");

        // EIP-712 domain separation (simplified).
        // Real usage: you'd define a typed data domain & struct hash more robustly
        bytes32 messageHash = keccak256(
            abi.encodePacked(msg.sender, certHash, expiry, address(this))
        ).toEthSignedMessageHash();

        address signer = messageHash.recover(typedSig);
        require(signer == trustedCA, "Invalid CA signature");

        userCerts[msg.sender] = Certificate(certHash, expiry);

        emit CertStored(msg.sender, certHash, expiry);
    }

    // Check if user is authenticated
    function isAuthenticated(address user) external view returns (bool) {
        Certificate memory c = userCerts[user];
        if (c.certHash == bytes32(0)) return false;
        if (block.timestamp > c.expiry) return false;
        return true;
    }
}
