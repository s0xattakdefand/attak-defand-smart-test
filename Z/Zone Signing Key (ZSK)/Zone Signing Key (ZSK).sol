// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title ZoneSigningKeyRegistry — Verifies signed zone records via ZSK + supports rotation
contract ZoneSigningKeyRegistry {
    using ECDSA for bytes32;

    address public admin;
    address public currentZSK;
    mapping(bytes32 => bool) public usedNonces;
    mapping(bytes32 => string) public zoneRecords;

    event ZSKRotated(address indexed newZSK);
    event ZoneRecordVerified(string indexed domain, string record, bytes32 nonce);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(address _initialZSK) {
        admin = msg.sender;
        currentZSK = _initialZSK;
    }

    /// 🔐 Rotate Zone Signing Key
    function rotateZSK(address newZSK) external onlyAdmin {
        require(newZSK != address(0), "Invalid ZSK");
        currentZSK = newZSK;
        emit ZSKRotated(newZSK);
    }

    /// ✅ Submit and verify signed zone record (with nonce + expiration)
    function verifyZoneRecord(
        string calldata domain,
        string calldata record,
        bytes32 nonce,
        uint256 expiration,
        bytes calldata signature
    ) external {
        require(block.timestamp <= expiration, "Signature expired");
        require(!usedNonces[nonce], "Replay detected");

        bytes32 hash = keccak256(abi.encodePacked(domain, record, nonce, expiration)).toEthSignedMessageHash();
        address signer = hash.recover(signature);
        require(signer == currentZSK, "Invalid ZSK signature");

        usedNonces[nonce] = true;
        zoneRecords[keccak256(abi.encodePacked(domain))] = record;

        emit ZoneRecordVerified(domain, record, nonce);
    }

    /// Read zone record by domain
    function getZoneRecord(string calldata domain) external view returns (string memory) {
        return zoneRecords[keccak256(abi.encodePacked(domain))];
    }
}
