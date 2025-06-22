contract BytecodeRecon {
    mapping(bytes32 => string) public labels;

    function labelHash(bytes32 hash, string calldata label) external {
        labels[hash] = label;
    }

    function resolve(address target) external view returns (string memory) {
        return labels[keccak256(target.code)];
    }
}
