import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";

contract SoulboundIdentity is ERC721URIStorage {
    constructor() ERC721("SBT Identity", "SBTID") {}

    function mint(address to, string memory metadataURI) external {
        uint256 tokenId = uint160(to);
        _mint(to, tokenId);
        _setTokenURI(tokenId, metadataURI);
    }

    function _transfer(address, address, uint256) internal pure override {
        revert("Soulbound: non-transferable");
    }
}
