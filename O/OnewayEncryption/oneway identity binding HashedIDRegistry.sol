contract HashedIDRegistry {
    mapping(bytes32 => bool) public registered;

    event Registered(bytes32 idHash);

    function register(bytes32 idHash) external {
        require(!registered[idHash], "Already registered");
        registered[idHash] = true;
        emit Registered(idHash);
    }

    function isRegistered(bytes32 idHash) external view returns (bool) {
        return registered[idHash];
    }
}
