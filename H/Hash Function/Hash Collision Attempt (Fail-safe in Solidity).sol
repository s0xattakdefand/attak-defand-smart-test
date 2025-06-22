contract HashCollisionDemo {
    mapping(bytes32 => bool) public used;

    function commit(string memory data) external {
        bytes32 hash = keccak256(abi.encodePacked(data));
        require(!used[hash], "Hash already used");
        used[hash] = true;
    }
}
