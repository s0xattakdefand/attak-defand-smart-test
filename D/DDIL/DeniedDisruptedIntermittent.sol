// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * SERVICE AVAILABILITY CONTROLLER
 * — Models “Denied / Disrupted / Intermittent” availability states
 *   for a critical service, with role‐based state management and
 *   event logging.
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
    bytes32 public constant SETTER_ROLE = keccak256("SETTER_ROLE");
    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(SETTER_ROLE, msg.sender);
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
/// SECTION 2 — AvailabilityState Machine
/// -------------------------------------------------------------------------
contract AvailabilityController is RBAC {
    enum Availability { Available, Denied, Disrupted, Intermittent }

    Availability public currentState;

    event StateChanged(Availability indexed oldState, Availability indexed newState, address indexed by);
    event ServiceAccessed(address indexed user, Availability state, uint256 timestamp);

    /// @notice Set the service availability state
    /// @dev Only SETTER_ROLE may call
    function setState(Availability newState) external onlyRole(SETTER_ROLE) {
        Availability old = currentState;
        require(old != newState, "Already in that state");
        currentState = newState;
        emit StateChanged(old, newState, msg.sender);
    }

    /// @notice Attempt to use the service
    /// @dev Succeeds only if state is Available or Intermittent (with warning)
    function useService() external {
        Availability st = currentState;
        require(st != Availability.Denied,     "Service is denied");
        require(st != Availability.Disrupted,  "Service is disrupted");
        // Intermittent: allow but emits warning via ServiceAccessed
        emit ServiceAccessed(msg.sender, st, block.timestamp);
        // ... actual service logic would go here ...
    }

    /// @notice Health check: returns current state
    function getState() external view returns (Availability) {
        return currentState;
    }
}
