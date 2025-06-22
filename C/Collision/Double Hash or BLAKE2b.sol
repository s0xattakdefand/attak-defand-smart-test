contract DoubleHash {
    function doubleHash(bytes memory data) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(data)));
    }
}
