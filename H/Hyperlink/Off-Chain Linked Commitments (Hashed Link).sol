contract HyperlinkCommitment {
    mapping(bytes32 => bool) public committedLinks;

    function commitLink(string memory url) external {
        committedLinks[keccak256(abi.encodePacked(url))] = true;
    }

    function verifyLink(string memory url) external view returns (bool) {
        return committedLinks[keccak256(abi.encodePacked(url))];
    }
}
