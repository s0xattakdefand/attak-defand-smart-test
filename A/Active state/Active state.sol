// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Web3 Active State Controller
contract ActiveStateRegistry {
    address public admin;

    struct State {
        bool active;
        uint256 expiresAt; // optional expiry
    }

    mapping(address => State) public userStates;
    mapping(bytes32 => State) public moduleStates;

    event StateActivated(address indexed user, uint256 expiresAt);
    event StateRevoked(address indexed user);
    event ModuleActivated(bytes32 indexed id, uint256 expiresAt);
    event ModuleRevoked(bytes32 indexed id);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    modifier isActive(address user) {
        State memory s = userStates[user];
        require(s.active, "Not active");
        require(s.expiresAt == 0 || block.timestamp < s.expiresAt, "Expired");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // User active state management
    function activateUser(address user, uint256 ttl) external onlyAdmin {
        userStates[user] = State(true, ttl > 0 ? block.timestamp + ttl : 0);
        emit StateActivated(user, userStates[user].expiresAt);
    }

    function revokeUser(address user) external onlyAdmin {
        delete userStates[user];
        emit StateRevoked(user);
    }

    // Module ID (e.g., hash of name/function)
    function activateModule(bytes32 moduleId, uint256 ttl) external onlyAdmin {
        moduleStates[moduleId] = State(true, ttl > 0 ? block.timestamp + ttl : 0);
        emit ModuleActivated(moduleId, moduleStates[moduleId].expiresAt);
    }

    function revokeModule(bytes32 moduleId) external onlyAdmin {
        delete moduleStates[moduleId];
        emit ModuleRevoked(moduleId);
    }

    // Example protected action
    function userAction() external isActive(msg.sender) {
        // only allowed if user is active
    }

    // Simulate attack
    function attackWithExpiredState(address target) external {
        State memory s = userStates[target];
        if (!s.active || (s.expiresAt != 0 && block.timestamp >= s.expiresAt)) {
            emit AttackDetected(msg.sender, "Tried using expired/inactive state");
            revert("Blocked expired state");
        }
    }

    function getUserState(address user) external view returns (bool active, uint256 expiresAt) {
        State memory s = userStates[user];
        return (s.active, s.expiresAt);
    }
}
