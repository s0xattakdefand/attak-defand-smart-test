// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AIARegistry — Authority Information Access pointer registry
contract AIARegistry {
    address public admin;

    struct AIA {
        string uri;           // IPFS/HTTPS to metadata or proof
        string role;          // e.g., ZK_VERIFIER, SIGNER, DAO_EXECUTOR
        bytes32 pubkeyHash;   // Hash of public key or credential
        uint256 expires;      // Timestamp
        bool active;
    }

    mapping(address => AIA) public authorities;

    event AIARegistered(address indexed authority, string role, string uri, bytes32 pubkeyHash);
    event AIARevoked(address indexed authority);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAIA(
        address authority,
        string calldata uri,
        string calldata role,
        bytes32 pubkeyHash,
        uint256 expires
    ) external onlyAdmin {
        authorities[authority] = AIA(uri, role, pubkeyHash, expires, true);
        emit AIARegistered(authority, role, uri, pubkeyHash);
    }

    function revokeAIA(address authority) external onlyAdmin {
        authorities[authority].active = false;
        emit AIARevoked(authority);
    }

    function getAIA(address authority) external view returns (AIA memory) {
        return authorities[authority];
    }

    function isActive(address authority) external view returns (bool) {
        AIA memory aia = authorities[authority];
        return aia.active && block.timestamp < aia.expires;
    }
}
