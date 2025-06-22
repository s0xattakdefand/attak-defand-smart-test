contract OneWayAccessGuard {
    bytes32 public immutable rootHash;

    constructor(bytes32 _root) {
        rootHash = _root;
    }

    function access(string calldata input) external view returns (bool) {
        return keccak256(abi.encodePacked(input)) == rootHash;
    }
}
