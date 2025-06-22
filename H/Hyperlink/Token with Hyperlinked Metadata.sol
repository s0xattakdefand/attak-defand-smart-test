// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract HyperlinkedNFT is ERC721URIStorage, Ownable {
    uint256 public nextId;

    constructor() ERC721("HyperlinkNFT", "HLNFT") {}

    function mint(string memory ipfsURI) external onlyOwner {
        _mint(msg.sender, nextId);
        _setTokenURI(nextId, ipfsURI); // 🔗 stores hyperlink to metadata
        nextId++;
    }
}
