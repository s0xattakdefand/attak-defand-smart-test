// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * Data Use Agreement Demo – Fixed
 * Removes incorrect `view` specifier from accessData so that it can emit events
 * and modify accessLog.
 */

/// @dev Simple Ownable implementation
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: not owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/// @dev Role-based access control for RECIPIENT role
abstract contract RBAC is Ownable {
    bytes32 public constant RECIPIENT = keccak256("RECIPIENT");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    constructor() {
        _grantRole(RECIPIENT, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address acct) external onlyOwner {
        _grantRole(role, acct);
    }

    function revokeRole(bytes32 role, address acct) external onlyOwner {
        _revokeRole(role, acct);
    }

    function hasRole(bytes32 role, address acct) public view returns (bool) {
        return _roles[role][acct];
    }

    function _grantRole(bytes32 role, address acct) internal {
        if (!_roles[role][acct]) {
            _roles[role][acct] = true;
            emit RoleGranted(role, acct);
        }
    }

    function _revokeRole(bytes32 role, address acct) internal {
        if (_roles[role][acct]) {
            _roles[role][acct] = false;
            emit RoleRevoked(role, acct);
        }
    }
}

/// @title DataUseAgreement
/// @dev Enforces on‐chain agreement terms between provider and recipients.
contract DataUseAgreement is RBAC {
    struct Agreement {
        address provider;
        bool    exists;
        uint256 expiry;         // UNIX timestamp when access ends
        string[] permittedOps;  // e.g. ["read","analytics"]
        bool    revoked;
    }

    // dataId => agreement terms
    mapping(bytes32 => Agreement) public agreements;
    // dataId => list of recipient addresses who accessed
    mapping(bytes32 => address[]) public accessLog;

    event AgreementCreated(
        bytes32 indexed dataId,
        address indexed provider,
        uint256 expiry,
        string[] permittedOps
    );
    event AgreementRevoked(bytes32 indexed dataId);
    event DataAccessed(bytes32 indexed dataId, address indexed recipient);

    /// @notice Provider defines terms for a dataId
    function createAgreement(
        bytes32 dataId,
        uint256 expiry,
        string[] calldata permittedOps
    ) external {
        require(!agreements[dataId].exists, "Agreement exists");
        agreements[dataId] = Agreement({
            provider: msg.sender,
            exists:   true,
            expiry:   expiry,
            permittedOps: permittedOps,
            revoked:  false
        });
        emit AgreementCreated(dataId, msg.sender, expiry, permittedOps);
    }

    /// @notice Provider may revoke the agreement at any time
    function revokeAgreement(bytes32 dataId) external {
        Agreement storage ag = agreements[dataId];
        require(ag.exists, "No such agreement");
        require(msg.sender == ag.provider, "Only provider");
        ag.revoked = true;
        emit AgreementRevoked(dataId);
    }

    /// @notice Recipient requests access under an operation name
    /// @dev **Not** declared `view` so it may update state and emit events.
    function accessData(
        bytes32 dataId,
        string calldata operation
    )
        external
        onlyRole(RECIPIENT)
    {
        Agreement storage ag = agreements[dataId];
        require(ag.exists, "No agreement");
        require(!ag.revoked, "Agreement revoked");
        require(block.timestamp <= ag.expiry, "Agreement expired");

        bool permitted = false;
        for (uint i = 0; i < ag.permittedOps.length; i++) {
            if (keccak256(bytes(ag.permittedOps[i])) == keccak256(bytes(operation))) {
                permitted = true;
                break;
            }
        }
        require(permitted, "Operation not permitted");

        // Record and emit access
        accessLog[dataId].push(msg.sender);
        emit DataAccessed(dataId, msg.sender);
    }

    /// @notice View the list of recipients who accessed a given dataId
    function getAccessLog(bytes32 dataId)
        external
        view
        returns (address[] memory)
    {
        return accessLog[dataId];
    }
}
