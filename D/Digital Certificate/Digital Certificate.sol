// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DigitalCertificateSuite.sol
/// @notice On‑chain analogues of “Digital Certificate” validation patterns:
///   Types: X509, PGP, SSL_TLS, CodeSigning  
///   AttackTypes: Forgery, RevocationCircumvention, KeyCompromise, MitM  
///   DefenseTypes: SignatureValidation, CRLCheck, OCSPCheck, CertificatePinning  

enum DigitalCertificateType       { X509, PGP, SSL_TLS, CodeSigning }
enum DigitalCertificateAttackType { Forgery, RevocationCircumvention, KeyCompromise, MitM }
enum DigitalCertificateDefenseType{ SignatureValidation, CRLCheck, OCSPCheck, CertificatePinning }

error DC__InvalidSignature();
error DC__Revoked();
error DC__Expired();
error DC__NotPinned();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE: No certificate validation
///
///    • accepts any cert as valid  
///    • Attack: Forgery, MitM  
///─────────────────────────────────────────────────────────────────────────────
contract DigitalCertificateVuln {
    event CertificateValidated(
        address indexed who,
        DigitalCertificateType  ctype,
        bytes                   cert,
        bool                    valid,
        DigitalCertificateAttackType attack
    );

    /// ❌ no checks: always returns valid
    function validateCertificate(DigitalCertificateType ctype, bytes calldata cert) external {
        emit CertificateValidated(msg.sender, ctype, cert, true, DigitalCertificateAttackType.Forgery);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: Forge or replay certificates
///
///    • Attack: Forgery, RevocationCircumvention  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DigitalCertificate {
    DigitalCertificateVuln public target;
    constructor(DigitalCertificateVuln _t) { target = _t; }

    /// submit a forged certificate
    function forge(DigitalCertificateType ctype, bytes calldata fakeCert) external {
        target.validateCertificate(ctype, fakeCert);
    }

    /// replay a revoked certificate
    function replay(DigitalCertificateType ctype, bytes calldata oldCert) external {
        target.validateCertificate(ctype, oldCert);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE: Signature + CRL revocation check
///
///    • Defense: SignatureValidation, CRLCheck  
///─────────────────────────────────────────────────────────────────────────────
contract DigitalCertificateSafe {
    mapping(bytes32 => bool) public trustedCA;
    mapping(bytes32 => bool) public revokedSerial;
    event CertificateValidated(
        address indexed who,
        DigitalCertificateType  ctype,
        bytes                   cert,
        DigitalCertificateDefenseType defense
    );

    constructor(bytes32[] memory caKeys, bytes32[] memory revoked) {
        for (uint i; i < caKeys.length; i++) trustedCA[caKeys[i]] = true;
        for (uint i; i < revoked.length; i++) revokedSerial[revoked[i]] = true;
    }

    /// ✅ check signature against trusted CA and CRL list
    /// cert format stub: abi.encodePacked(serial, caKey, sig, expiry)
    function validateCertificate(
        DigitalCertificateType ctype,
        bytes calldata cert
    ) external {
        // parse stub fields
        require(cert.length >= 96, "cert too short");
        bytes32 serial;
        bytes32 caKey;
        bytes32 sig;
        uint64  expiry;
        assembly {
            serial  := calldataload(cert.offset)
            caKey   := calldataload(add(cert.offset,32))
            sig     := calldataload(add(cert.offset,64))
            expiry  := shr(192, calldataload(add(cert.offset,96)))
        }
        // signature validation stub: require CA trusted
        if (!trustedCA[caKey]) revert DC__InvalidSignature();
        // revocation check
        if (revokedSerial[serial]) revert DC__Revoked();
        // expiration check
        if (block.timestamp > expiry) revert DC__Expired();
        emit CertificateValidated(msg.sender, ctype, cert, DigitalCertificateDefenseType.SignatureValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE ADVANCED: OCSP + Certificate Pinning
///
///    • Defense: OCSPCheck, CertificatePinning  
///─────────────────────────────────────────────────────────────────────────────
contract DigitalCertificateSafeAdvanced {
    mapping(bytes32 => bool) public ocspGood;
    mapping(address => bytes32) public pinnedCert;
    event CertificateValidated(
        address indexed who,
        DigitalCertificateType  ctype,
        bytes                   cert,
        DigitalCertificateDefenseType defense
    );

    /// owner seeds OCSP responses and client pins
    address public owner;
    constructor() { owner = msg.sender; }

    function setOCSPStatus(bytes32 serial, bool good) external {
        require(msg.sender == owner, "only owner");
        ocspGood[serial] = good;
    }

    function pinCertificate(address client, bytes32 serial) external {
        require(msg.sender == owner, "only owner");
        pinnedCert[client] = serial;
    }

    /// ✅ check OCSP and enforce pinning for caller
    /// cert format stub: abi.encodePacked(serial, _, _, expiry)
    function validateCertificate(
        DigitalCertificateType ctype,
        bytes calldata cert
    ) external {
        // parse serial and expiry
        require(cert.length >= 40, "cert too short");
        bytes32 serial;
        uint64  expiry;
        assembly {
            serial := calldataload(cert.offset)
            expiry := shr(192, calldataload(add(cert.offset,32)))
        }
        // OCSP check
        if (!ocspGood[serial]) revert DC__Revoked();
        // expiration
        if (block.timestamp > expiry) revert DC__Expired();
        // client pin check
        if (pinnedCert[msg.sender] != bytes32(0) && pinnedCert[msg.sender] != serial) {
            revert DC__NotPinned();
        }
        emit CertificateValidated(msg.sender, ctype, cert, DigitalCertificateDefenseType.OCSPCheck);
    }
}
