// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GenericTokenCardAttackDefense - Full Attack and Defense Simulation for Generic Token Card in Web3 Smart Contracts
/// @author ChatGPT

import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Insecure Generic Token Card (Vulnerable to Unlimited Minting and Metadata Injection)
contract InsecureGenericTokenCard is ERC721URIStorage {
    uint256 public nextTokenId;

    constructor() ERC721("InsecureGenericCard", "IGC") {}

    function mintCard(address to, string memory uri) external {
        _safeMint(to, nextTokenId);
        _setTokenURI(nextTokenId, uri);
        nextTokenId++;
    }
}

/// @notice Secure Generic Token Card (Mint Authorization + Metadata Integrity)
contract SecureGenericTokenCard is ERC721URIStorage, Ownable {
    uint256 public nextTokenId;
    mapping(bytes32 => bool) public usedMetadataHashes;
    mapping(address => bool) public authorizedMinters;

    event CardMinted(address indexed minter, address indexed recipient, uint256 indexed tokenId, bytes32 metadataHash);

    constructor() ERC721("SecureGenericCard", "SGC") {}

    modifier onlyAuthorized() {
        require(authorizedMinters[msg.sender], "Not authorized minter");
        _;
    }

    function authorizeMinter(address minter) external onlyOwner {
        authorizedMinters[minter] = true;
    }

    function revokeMinter(address minter) external onlyOwner {
        authorizedMinters[minter] = false;
    }

    function mintCard(address to, string memory uri, bytes32 expectedMetadataHash) external onlyAuthorized {
        bytes32 actualHash = keccak256(abi.encodePacked(uri));
        require(expectedMetadataHash == actualHash, "Metadata hash mismatch");
        require(!usedMetadataHashes[expectedMetadataHash], "Metadata hash already used");

        usedMetadataHashes[expectedMetadataHash] = true;

        _safeMint(to, nextTokenId);
        _setTokenURI(nextTokenId, uri);

        emit CardMinted(msg.sender, to, nextTokenId, expectedMetadataHash);

        nextTokenId++;
    }
}

/// @notice Attack contract simulating unlimited minting and metadata spoofing
contract GenericTokenCardIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function abuseMint(address attacker, string memory fakeURI) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("mintCard(address,string)", attacker, fakeURI)
        );
    }
}
