contract IdentityRegistry {
    mapping(address => bool) public whitelisted;
    event Registered(address indexed user);
    event Removed(address indexed user);

    function register(address user) external {
        whitelisted[user] = true;
        emit Registered(user);
    }

    function remove(address user) external {
        whitelisted[user] = false;
        emit Removed(user);
    }
}
