contract DomainSeparatedHash {
    function domainHash(string memory domain, bytes memory data) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(domain, data));
    }
}
