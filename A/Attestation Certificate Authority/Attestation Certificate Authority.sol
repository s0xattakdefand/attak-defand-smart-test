// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Fake Attestation, Replay Attack, Untrusted ACA
/// Defense Types: EIP-191 Signature Check, ACA Registry, Replay Protection

contract AttestationCertificateAuthority {
    address public rootAdmin;

    mapping(address => bool) public trustedACAs;
    mapping(bytes32 => bool) public usedAttestationHashes;

    event ACARegistered(address indexed aca);
    event ACARevoked(address indexed aca);
    event AttestationVerified(address indexed subject, string attribute);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        rootAdmin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == rootAdmin, "Only admin");
        _;
    }

    /// DEFENSE: Register a trusted ACA
    function registerACA(address aca) external onlyAdmin {
        trustedACAs[aca] = true;
        emit ACARegistered(aca);
    }

    /// DEFENSE: Revoke a compromised ACA
    function revokeACA(address aca) external onlyAdmin {
        trustedACAs[aca] = false;
        emit ACARevoked(aca);
    }

    /// DEFENSE: Verify an attestation (EIP-191 style)
    /// - subject: who the attestation is about
    /// - attribute: string like "DOCTOR_ASIA"
    /// - nonce: anti-replay
    /// - sig: ACA-signed attestation hash
    function verifyAttestation(
        address subject,
        string calldata attribute,
        uint256 nonce,
        bytes calldata sig
    ) external returns (bool) {
        bytes32 message = keccak256(abi.encodePacked(subject, attribute, nonce));
        require(!usedAttestationHashes[message], "Replay detected");

        bytes32 ethSignedMessage = ECDSA.toEthSignedMessageHash(message);
        address signer = ECDSA.recover(ethSignedMessage, sig);

        if (!trustedACAs[signer]) {
            emit AttackDetected(msg.sender, "Untrusted ACA signer");
            revert("Untrusted certificate authority");
        }

        usedAttestationHashes[message] = true;
        emit AttestationVerified(subject, attribute);
        return true;
    }
}

library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }

        return ecrecover(hash, v, r, s);
    }
}
