// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DERIVED PIV CREDENTIAL MANAGEMENT SYSTEM
 * — Manages issuance, revocation, and validation of Derived PIV Credentials.
 * Sources: NIST SP 800-79-2, PIV Derived Credential guidelines.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — Ownable & RBAC helpers
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }
    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not owner");
        _;
    }
    function owner() public view returns (address) {
        return _owner;
    }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant PIV_CA_ROLE    = keccak256("PIV_CA_ROLE");    // can issue/revoke
    bytes32 public constant RP_ROLE        = keccak256("RP_ROLE");        // relying party, can validate

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(PIV_CA_ROLE, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — Derived PIV Credential Management
/// -------------------------------------------------------------------------
contract DerivedPIVCredentialMS is RBAC {
    enum Status { NONE, ACTIVE, REVOKED }

    struct Credential {
        bytes32 pointer;    // off‐chain encrypted credential pointer (e.g. IPFS CID)
        uint256 issuedAt;
        Status  status;
        uint256 revokedAt;
    }

    mapping(address => Credential) private _creds;

    event CredentialIssued(address indexed holder, bytes32 pointer, uint256 issuedAt);
    event CredentialRevoked(address indexed holder, uint256 revokedAt);
    event CredentialValidated(address indexed holder, address indexed rp, uint256 validatedAt);

    /// @notice Issue a Derived PIV Credential to a holder
    /// @param holder    The subject address (e.g. holder’s wallet)
    /// @param pointer   Keccak256 hash or IPFS CID of the encrypted credential
    function issueCredential(address holder, bytes32 pointer)
        external
        onlyRole(PIV_CA_ROLE)
    {
        require(_creds[holder].status != Status.ACTIVE, "Already active");
        _creds[holder] = Credential({
            pointer:   pointer,
            issuedAt:  block.timestamp,
            status:    Status.ACTIVE,
            revokedAt: 0
        });
        emit CredentialIssued(holder, pointer, block.timestamp);
    }

    /// @notice Revoke an existing Derived PIV Credential
    /// @param holder    The subject address whose credential is revoked
    function revokeCredential(address holder)
        external
        onlyRole(PIV_CA_ROLE)
    {
        Credential storage c = _creds[holder];
        require(c.status == Status.ACTIVE, "Not active");
        c.status = Status.REVOKED;
        c.revokedAt = block.timestamp;
        emit CredentialRevoked(holder, block.timestamp);
    }

    /// @notice Validate a holder’s credential by a relying party
    /// @param holder    The subject whose credential is being validated
    function validateCredential(address holder)
        external
        onlyRole(RP_ROLE)
        returns (bool)
    {
        Credential storage c = _creds[holder];
        require(c.status == Status.ACTIVE, "Credential not active");
        emit CredentialValidated(holder, msg.sender, block.timestamp);
        return true;
    }

    /// @notice Fetch credential metadata (pointer, issuance, status)
    function getCredential(address holder)
        external
        view
        returns (
            bytes32 pointer,
            uint256 issuedAt,
            Status  status,
            uint256 revokedAt
        )
    {
        Credential storage c = _creds[holder];
        return (c.pointer, c.issuedAt, c.status, c.revokedAt);
    }
}
