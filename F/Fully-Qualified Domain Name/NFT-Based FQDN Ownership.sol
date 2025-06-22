// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract FQDNnft is ERC721 {
    uint256 public nextId = 1;
    mapping(string => uint256) public fqdnToToken;

    constructor() ERC721("FQDN", "FQDN") {}

    function mintFQDN(string calldata fqdn) external {
        require(fqdnToToken[fqdn] == 0, "Already claimed");
        fqdnToToken[fqdn] = nextId;
        _mint(msg.sender, nextId++);
    }

    function resolve(string calldata fqdn) external view returns (address) {
        return ownerOf(fqdnToToken[fqdn]);
    }
}
