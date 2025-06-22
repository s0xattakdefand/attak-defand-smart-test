contract Sha256Example {
    function getHash(string memory input) external pure returns (bytes32) {
        return sha256(abi.encodePacked(input));
    }
}
