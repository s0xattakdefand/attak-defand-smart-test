contract RoleRiskRegistry {
    mapping(bytes32 => address) public roleOwners;

    event RoleMutated(bytes32 role, address newOwner);

    function set(bytes32 role, address owner) external {
        roleOwners[role] = owner;
        emit RoleMutated(role, owner);
    }

    function check(bytes32 role) external view returns (bool) {
        return roleOwners[role] != address(0);
    }
}
