contract HashPreimageRegistry {
    mapping(bytes32 => string) public labels;

    function bind(bytes32 hash, string calldata label) external {
        labels[hash] = label;
    }

    function resolve(bytes32 hash) external view returns (string memory) {
        return labels[hash];
    }
}
