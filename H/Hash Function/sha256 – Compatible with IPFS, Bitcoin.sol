contract Sha256Hasher {
    function hashString(string memory input) public pure returns (bytes32) {
        return sha256(abi.encodePacked(input));
    }
}
