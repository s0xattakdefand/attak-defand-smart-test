// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * A simplified certificate check:
 * - We store CA public keys on chain
 * - Each certificate is hashed & signed by the CA
 * - We verify that signature + optional expiry
 */
contract CertificateAuthSecure {
    using ECDSA for bytes32;

    // Mapping of CA -> true if recognized
    mapping(address => bool) public trustedCAs;

    struct Certificate {
        bytes32 certHash;
        uint256 expiry;
    }

    mapping(address => Certificate) public userCerts;

    event CAAdded(address ca);
    event CertStored(address user, bytes32 certHash, uint256 expiry);

    constructor(address[] memory initialCAs) {
        for (uint i = 0; i < initialCAs.length; i++) {
            trustedCAs[initialCAs[i]] = true;
            emit CAAdded(initialCAs[i]);
        }
    }

    function addCA(address ca) external {
        // In reality, only contract owner or governance can call
        trustedCAs[ca] = true;
        emit CAAdded(ca);
    }

    // user provides certHash + CA signature + expiry
    function storeCertificate(bytes32 certHash, uint256 expiry, bytes calldata caSig) external {
        // Ensure not expired
        require(expiry > block.timestamp, "Cert expired on arrival");

        // Recreate the message the CA signs: (user, certHash, expiry)
        bytes32 message = keccak256(abi.encodePacked(msg.sender, certHash, expiry))
            .toEthSignedMessageHash();

        // Recover signer from CA signature
        address signer = message.recover(caSig);
        require(trustedCAs[signer], "Untrusted CA or invalid signature");

        userCerts[msg.sender] = Certificate(certHash, expiry);
        emit CertStored(msg.sender, certHash, expiry);
    }

    function isAuthenticated(address user) external view returns (bool) {
        Certificate memory cert = userCerts[user];
        if (cert.certHash == bytes32(0)) return false;
        if (block.timestamp > cert.expiry) return false;
        return true;
    }
}
