contract BytecodePatternMap {
    mapping(bytes32 => string) public fingerprints;

    function register(bytes32 codeHash, string calldata label) external {
        fingerprints[codeHash] = label;
    }

    function lookup(address target) external view returns (string memory) {
        return fingerprints[keccak256(target.code)];
    }
}
