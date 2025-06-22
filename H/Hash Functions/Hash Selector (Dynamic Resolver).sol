contract HashFunctionSelector {
    enum HashType { KECCAK256, SHA256, RIPEMD160 }

    function hash(HashType h, string calldata input) external pure returns (bytes memory) {
        if (h == HashType.KECCAK256) return abi.encodePacked(keccak256(abi.encodePacked(input)));
        if (h == HashType.SHA256) return abi.encodePacked(sha256(abi.encodePacked(input)));
        if (h == HashType.RIPEMD160) return abi.encodePacked(ripemd160(abi.encodePacked(input)));
        revert("Unknown hash");
    }
}
