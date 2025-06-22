contract RBACGuardWithLogger is RBACGuard {
    RoleUsageLogger public logger;

    constructor(address _uplink, address _logger) RBACGuard(_uplink) {
        logger = RoleUsageLogger(_logger);
    }

    modifier tracked(bytes32 role) {
        logger.log(role, msg.sig);
        _;
    }

    function grant(address user, bytes32 role) external onlyRole(adminOf[role]) tracked(adminOf[role]) {
        hasRole[user][role] = true;
        uplink.pushRoleMutation("grant", user, role);
    }

    function revoke(address user, bytes32 role) external onlyRole(adminOf[role]) tracked(adminOf[role]) {
        hasRole[user][role] = false;
        uplink.pushRoleMutation("revoke", user, role);
    }
}
