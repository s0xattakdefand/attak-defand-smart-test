// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CDROMRegistry {
    address public admin;

    struct CDROM {
        string title;
        string metadataURI;     // IPFS or Arweave URI
        bytes32 contentHash;    // keccak256 or IPFS multihash
        uint256 registeredAt;
        bool frozen;
    }

    mapping(uint256 => CDROM) public discs;
    uint256 public totalDiscs;

    event CDROMBurned(uint256 indexed id, string title, bytes32 contentHash);
    event CDROMFrozen(uint256 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function burnCD(string calldata title, string calldata metadataURI, bytes32 contentHash) external onlyAdmin returns (uint256 id) {
        id = totalDiscs++;
        discs[id] = CDROM({
            title: title,
            metadataURI: metadataURI,
            contentHash: contentHash,
            registeredAt: block.timestamp,
            frozen: false
        });

        emit CDROMBurned(id, title, contentHash);
    }

    function freezeCD(uint256 id) external onlyAdmin {
        require(!discs[id].frozen, "Already frozen");
        discs[id].frozen = true;
        emit CDROMFrozen(id);
    }

    function getCD(uint256 id) external view returns (
        string memory title,
        string memory metadataURI,
        bytes32 contentHash,
        uint256 registeredAt,
        bool frozen
    ) {
        CDROM memory c = discs[id];
        return (c.title, c.metadataURI, c.contentHash, c.registeredAt, c.frozen);
    }

    function verifyHash(uint256 id, bytes32 inputHash) external view returns (bool) {
        return discs[id].frozen && discs[id].contentHash == inputHash;
    }
}
