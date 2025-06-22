// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";

contract NFTHandleResolver {
    IERC721 public handleNFT;

    constructor(address nft) {
        handleNFT = IERC721(nft);
    }

    function resolveByTokenId(uint256 id) external view returns (address) {
        return handleNFT.ownerOf(id);
    }
}
