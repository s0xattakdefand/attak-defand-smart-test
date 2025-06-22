// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Forged Cert, Expired Use, Wildcard Scope
/// Defense Types: Issuer Check, Expiry, Scope Binding

contract AcmeCertificateAuthority {
    address public trustedIssuer;

    struct Certificate {
        address subject;
        bytes32 scopeHash; // e.g., hash of "zkLoginDAO", "oracleFeed"
        uint256 issuedAt;
        uint256 expiresAt;
        bool revoked;
    }

    mapping(bytes32 => Certificate) public certificates;

    event CertificateIssued(bytes32 certId, address subject, bytes32 scope, uint256 expiry);
    event CertificateRevoked(bytes32 certId);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyIssuer() {
        require(msg.sender == trustedIssuer, "Not authorized issuer");
        _;
    }

    constructor(address _issuer) {
        trustedIssuer = _issuer;
    }

    /// DEFENSE: Issue scoped + expirable cert
    function issueCertificate(address subject, bytes32 scopeHash, uint256 ttl) external onlyIssuer returns (bytes32) {
        bytes32 certId = keccak256(abi.encodePacked(subject, scopeHash, block.timestamp));
        certificates[certId] = Certificate(subject, scopeHash, block.timestamp, block.timestamp + ttl, false);
        emit CertificateIssued(certId, subject, scopeHash, block.timestamp + ttl);
        return certId;
    }

    /// DEFENSE: Revoke certificate
    function revokeCertificate(bytes32 certId) external onlyIssuer {
        Certificate storage cert = certificates[certId];
        cert.revoked = true;
        emit CertificateRevoked(certId);
    }

    /// View + validate cert
    function validateCertificate(bytes32 certId, bytes32 requiredScope) external view returns (bool) {
        Certificate memory cert = certificates[certId];
        if (
            cert.revoked ||
            block.timestamp > cert.expiresAt ||
            cert.scopeHash != requiredScope
        ) return false;
        return true;
    }

    /// ATTACK: Simulate fake cert usage
    function attackFakeCertificate(bytes32 fakeId, bytes32 scope) external {
        emit AttackDetected(msg.sender, "Forged certificate used");
        revert("Certificate validation failed");
    }

    /// View cert info
    function getCertificate(bytes32 certId) external view returns (Certificate memory) {
        return certificates[certId];
    }
}
