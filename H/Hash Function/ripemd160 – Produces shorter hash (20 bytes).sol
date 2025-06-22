contract Ripemd160Hasher {
    function hashString(string memory input) public pure returns (bytes20) {
        return ripemd160(abi.encodePacked(input));
    }
}
