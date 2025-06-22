contract RARPBytecodeResolver {
    mapping(bytes32 => string) public versionLabel;

    function registerVersion(address logic, string calldata version) external {
        bytes32 hash = keccak256(logic.code);
        versionLabel[hash] = version;
    }

    function resolve(address logic) external view returns (string memory) {
        return versionLabel[keccak256(logic.code)];
    }
}
