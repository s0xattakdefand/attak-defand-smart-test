contract PreimageDriftTracker {
    mapping(bytes32 => uint256) public usage;
    mapping(bytes32 => address[]) public users;

    event Drift(bytes32 hash, address user, uint256 count);

    function track(string calldata preimage) external {
        bytes32 hash = keccak256(abi.encodePacked(preimage));
        usage[hash]++;
        users[hash].push(msg.sender);
        emit Drift(hash, msg.sender, usage[hash]);
    }

    function isReused(bytes32 hash) external view returns (bool) {
        return usage[hash] > 1;
    }

    function getUsers(bytes32 hash) external view returns (address[] memory) {
        return users[hash];
    }
}
