// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATA CENTER GROUP MANAGEMENT
 * — “A logical grouping of one or more data centers under a common administrative domain.”
 *   Provides on-chain governance: group creation, admin assignment, data-center membership,
 *   and full event logging.
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
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant GROUP_ADMIN_ROLE = keccak256("GROUP_ADMIN_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(GROUP_ADMIN_ROLE, msg.sender);
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
/// SECTION 2 — DataCenterGroup contract
/// -------------------------------------------------------------------------
contract DataCenterGroup is RBAC {
    struct Group {
        string   name;
        address  admin;
        bool     exists;
    }

    // groupId ⇒ Group metadata
    mapping(uint256 => Group) public groups;
    uint256 public nextGroupId;

    // groupId ⇒ dataCenter ⇒ membership flag
    mapping(uint256 => mapping(address => bool)) public isMember;
    // groupId ⇒ list of data centers
    mapping(uint256 => address[]) public members;

    /// Events for audit logging
    event GroupCreated(uint256 indexed groupId, string name, address indexed admin);
    event GroupAdminChanged(uint256 indexed groupId, address indexed oldAdmin, address indexed newAdmin);
    event DataCenterAdded(uint256 indexed groupId, address indexed dataCenter);
    event DataCenterRemoved(uint256 indexed groupId, address indexed dataCenter);

    /// @notice Create a new data center group
    /// @param name  Descriptive name of the group
    /// @param admin Initial admin for this group
    function createGroup(string calldata name, address admin) external onlyRole(GROUP_ADMIN_ROLE) returns (uint256 groupId) {
        require(admin != address(0), "Invalid admin");
        groupId = nextGroupId++;
        groups[groupId] = Group({ name: name, admin: admin, exists: true });
        emit GroupCreated(groupId, name, admin);
    }

    /// @notice Change the admin of an existing group
    function changeGroupAdmin(uint256 groupId, address newAdmin) external {
        Group storage g = groups[groupId];
        require(g.exists, "Unknown group");
        require(msg.sender == g.admin, "Only group admin");
        require(newAdmin != address(0), "Invalid new admin");

        address old = g.admin;
        g.admin = newAdmin;
        emit GroupAdminChanged(groupId, old, newAdmin);
    }

    /// @notice Add a data center to a group
    function addDataCenter(uint256 groupId, address dataCenter) external {
        Group storage g = groups[groupId];
        require(g.exists, "Unknown group");
        require(msg.sender == g.admin, "Only group admin");
        require(!isMember[groupId][dataCenter], "Already a member");

        isMember[groupId][dataCenter] = true;
        members[groupId].push(dataCenter);
        emit DataCenterAdded(groupId, dataCenter);
    }

    /// @notice Remove a data center from a group
    function removeDataCenter(uint256 groupId, address dataCenter) external {
        Group storage g = groups[groupId];
        require(g.exists, "Unknown group");
        require(msg.sender == g.admin, "Only group admin");
        require(isMember[groupId][dataCenter], "Not a member");

        // Remove membership flag and array entry
        isMember[groupId][dataCenter] = false;
        address[] storage arr = members[groupId];
        for (uint i = 0; i < arr.length; i++) {
            if (arr[i] == dataCenter) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                break;
            }
        }

        emit DataCenterRemoved(groupId, dataCenter);
    }

    /// @notice List all members of a group
    function listMembers(uint256 groupId) external view returns (address[] memory) {
        require(groups[groupId].exists, "Unknown group");
        return members[groupId];
    }
}
