function namehash(string[] memory labels) public pure returns (bytes32 node) {
    node = bytes32(0);
    for (uint256 i = labels.length; i > 0; i--) {
        node = keccak256(abi.encodePacked(node, keccak256(bytes(labels[i - 1]))));
    }
}
