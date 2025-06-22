import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract NFTCustody is ERC721 {
    constructor() ERC721("CustodyNFT", "CNFT") {}

    // Standard NFT transfer automatically emits Transfer event,
    // which can serve as chain-of-custody record
}
