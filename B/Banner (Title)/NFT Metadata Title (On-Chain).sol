contract NFTBanner {
    mapping(uint256 => string) public tokenTitles;

    function setTokenTitle(uint256 tokenId, string calldata title) public {
        // In real life: require ownership of token
        tokenTitles[tokenId] = title;
    }

    function getTokenTitle(uint256 tokenId) public view returns (string memory) {
        return tokenTitles[tokenId];
    }
}
