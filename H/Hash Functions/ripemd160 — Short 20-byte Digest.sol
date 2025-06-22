contract Ripemd160Example {
    function getHash(string memory input) external pure returns (bytes20) {
        return ripemd160(abi.encodePacked(input));
    }
}
