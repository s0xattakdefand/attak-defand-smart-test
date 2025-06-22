function setTokenURI(uint256 tokenId, string calldata uri) external {
    require(bytes(uri).length > 8, "Invalid URI");
    require(bytes(uri)[0] == 'i', "Must start with i");
    // Example check: starts with `ipfs://`
}
