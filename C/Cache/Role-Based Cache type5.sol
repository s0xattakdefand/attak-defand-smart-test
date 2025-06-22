contract RoleCache {
    mapping(bytes32 => uint256) public cache; // e.g., role => value
    bytes32 public constant ADMIN = keccak256("ADMIN");

    function update(bytes32 role, uint256 value) public {
        require(role == ADMIN, "Only ADMIN can cache this"); // demo purpose
        cache[role] = value;
    }

    function get(bytes32 role) public view returns (uint256) {
        return cache[role];
    }
}
