interface IERC721 {
    function ownerOf(uint256 tokenId) external view returns (address);
}

contract NFTCertAuth {
    IERC721 public certificateNFT;
    function initializeCert(address nftAddress) external {
        certificateNFT = IERC721(nftAddress);
    }

    function isAuthenticated(address user, uint256 certTokenId) external view returns (bool) {
        return (certificateNFT.ownerOf(certTokenId) == user);
    }
}
