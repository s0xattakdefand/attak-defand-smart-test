contract DualHasher {
    function hashAll(string memory data) external pure returns (bytes32, bytes32, bytes20) {
        return (
            keccak256(abi.encodePacked(data)),
            sha256(abi.encodePacked(data)),
            ripemd160(abi.encodePacked(data))
        );
    }
}
