contract ENSHijack {
    mapping(bytes32 => address) public nameOwner;

    function register(string calldata name) external {
        nameOwner[keccak256(abi.encodePacked(name))] = msg.sender;
    }
}
