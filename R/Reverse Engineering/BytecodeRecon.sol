contract BytecodeRecon {
    mapping(bytes32 => string) public labels;

    function labelHash(bytes32 codeHash, string calldata label) external {
        labels[codeHash] = label;
    }

    function resolve(address addr) external view returns (string memory) {
        return labels[keccak256(addr.code)];
    }
}
