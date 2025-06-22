contract RoleRegistry {
    mapping(bytes32 => mapping(address => bool)) public hasRole;
    event RoleGranted(bytes32 indexed role, address user);
    event RoleRevoked(bytes32 indexed role, address user);

    function grantRole(bytes32 role, address user) external {
        hasRole[role][user] = true;
        emit RoleGranted(role, user);
    }

    function revokeRole(bytes32 role, address user) external {
        hasRole[role][user] = false;
        emit RoleRevoked(role, user);
    }
}
