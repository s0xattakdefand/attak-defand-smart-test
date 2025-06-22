// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CompactDiscRegistry {
    address public admin;

    struct CD {
        string title;
        string metadataURI;      // IPFS/Arweave URI
        bytes32 contentHash;     // keccak256 or IPFS CID
        address owner;
        uint256 mintedAt;
        bool frozen;
    }

    mapping(uint256 => CD) public cds;
    uint256 public totalCDs;

    event CDMinted(uint256 indexed cdId, string title, address indexed owner);
    event CDFrozen(uint256 indexed cdId, bytes32 contentHash);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyOwner(uint256 cdId) {
        require(msg.sender == cds[cdId].owner, "Not CD owner");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function mintCD(string calldata title, string calldata metadataURI, bytes32 contentHash) external returns (uint256 cdId) {
        cdId = totalCDs++;
        cds[cdId] = CD({
            title: title,
            metadataURI: metadataURI,
            contentHash: contentHash,
            owner: msg.sender,
            mintedAt: block.timestamp,
            frozen: false
        });

        emit CDMinted(cdId, title, msg.sender);
    }

    function freezeCD(uint256 cdId) external onlyOwner(cdId) {
        require(!cds[cdId].frozen, "Already frozen");
        cds[cdId].frozen = true;

        emit CDFrozen(cdId, cds[cdId].contentHash);
    }

    function getCD(uint256 cdId) external view returns (
        string memory title,
        string memory metadataURI,
        bytes32 contentHash,
        address owner,
        bool frozen,
        uint256 mintedAt
    ) {
        CD memory c = cds[cdId];
        return (c.title, c.metadataURI, c.contentHash, c.owner, c.frozen, c.mintedAt);
    }

    function verifyContent(uint256 cdId, bytes32 inputHash) external view returns (bool) {
        return cds[cdId].contentHash == inputHash && cds[cdId].frozen;
    }
}
