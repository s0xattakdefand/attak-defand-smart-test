contract LockedENS {
    mapping(bytes32 => address) public nameOwner;
    mapping(bytes32 => bool) public registered;

    function register(string calldata name) external {
        bytes32 node = keccak256(abi.encodePacked(name));
        require(!registered[node], "Already taken");
        nameOwner[node] = msg.sender;
        registered[node] = true;
    }
}
