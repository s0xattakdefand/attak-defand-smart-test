contract RoleRegistry {
    mapping(address => string) public role;

    function assign(address user, string calldata r) external {
        role[user] = r;
    }

    function check(address user, string calldata r) external view returns (bool) {
        return keccak256(bytes(role[user])) == keccak256(bytes(r));
    }
}
