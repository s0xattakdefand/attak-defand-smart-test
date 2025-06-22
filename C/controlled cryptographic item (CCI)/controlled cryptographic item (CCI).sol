// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

/// @title ControlledCryptoItem — Smart contract-managed cryptographic secret
contract ControlledCryptoItem is AccessControl {
    bytes32 public constant CCI_ADMIN = keccak256("CCI_ADMIN");
    bytes32 private cciHash;
    bool public used;

    event CCIInitialized(bytes32 indexed hash);
    event CCIAccessed(address indexed by, string label);
    event CCIRevoked(address indexed by);

    constructor(bytes32 _hash, address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CCI_ADMIN, admin);
        cciHash = _hash;
        emit CCIInitialized(_hash);
    }

    /// @notice Access the CCI only by revealing correct preimage
    function accessCCI(string calldata label, string calldata secret) external {
        require(!used, "CCI: already used");
        require(keccak256(abi.encodePacked(secret)) == cciHash, "CCI: invalid secret");
        used = true;
        emit CCIAccessed(msg.sender, label);
        // Use the secret (e.g., mint, unlock, etc.)
    }

    /// @notice Admin can revoke the CCI
    function revokeCCI() external onlyRole(CCI_ADMIN) {
        used = true;
        emit CCIRevoked(msg.sender);
    }

    /// @notice Replace secret hash with new one (timelock recommended offchain)
    function rotateCCI(bytes32 newHash) external onlyRole(CCI_ADMIN) {
        require(used, "CCI: must revoke before rotate");
        cciHash = newHash;
        used = false;
        emit CCIInitialized(newHash);
    }
}
