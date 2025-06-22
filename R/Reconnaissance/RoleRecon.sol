interface IRoleCheck {
    function hasRole(bytes32 role, address account) external view returns (bool);
}

contract RoleRecon {
    event RoleScan(bytes32 role, address account, bool hasAccess);

    function scanRole(address target, bytes32 role, address account) external {
        bool ok = IRoleCheck(target).hasRole(role, account);
        emit RoleScan(role, account, ok);
    }
}
