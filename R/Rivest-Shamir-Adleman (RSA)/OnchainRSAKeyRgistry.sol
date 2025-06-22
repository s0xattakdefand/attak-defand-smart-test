contract RSAKeyRegistry {
    struct PubKey {
        uint256 e;
        uint256 n;
        string label;
    }

    mapping(address => PubKey) public keys;

    function register(uint256 e, uint256 n, string calldata label) external {
        keys[msg.sender] = PubKey(e, n, label);
    }

    function get(address who) external view returns (PubKey memory) {
        return keys[who];
    }
}
