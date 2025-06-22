contract CommitmentShield {
    mapping(address => bytes32) public commitments;

    function commit(bytes32 hash) external {
        commitments[msg.sender] = hash;
    }

    function reveal(uint256 secret, bytes32 salt) external view returns (bool) {
        return keccak256(abi.encodePacked(secret, salt)) == commitments[msg.sender];
    }
}
