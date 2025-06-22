// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssuredInfoShare - Verifiable, access-controlled information sharing in Web3

contract AssuredInfoShare {
    address public admin;

    struct InfoShare {
        bytes32 id;
        bytes32 dataHash;           // Keccak256 of original payload
        address publisher;
        address[] allowedViewers;
        string category;            // e.g., "DAO-Proposal", "BridgeMsg", "ZKProof"
        uint256 validUntil;
        bool active;
    }

    mapping(bytes32 => InfoShare) public shares;
    bytes32[] public shareIds;

    event InfoShared(bytes32 indexed id, address indexed publisher, string category);
    event InfoAccessed(bytes32 indexed id, address indexed accessor);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function shareInfo(
        bytes32 dataHash,
        address[] calldata allowedViewers,
        string calldata category,
        uint256 validDuration
    ) external returns (bytes32 id) {
        id = keccak256(abi.encodePacked(dataHash, msg.sender, block.timestamp));
        shares[id] = InfoShare({
            id: id,
            dataHash: dataHash,
            publisher: msg.sender,
            allowedViewers: allowedViewers,
            category: category,
            validUntil: block.timestamp + validDuration,
            active: true
        });
        shareIds.push(id);
        emit InfoShared(id, msg.sender, category);
        return id;
    }

    function accessInfo(bytes32 id) external view returns (bytes32 dataHash) {
        InfoShare memory info = shares[id];
        require(info.active, "Inactive share");
        require(block.timestamp <= info.validUntil, "Share expired");
        require(isAuthorizedViewer(msg.sender, info.allowedViewers), "Access denied");
        return info.dataHash;
    }

    function isAuthorizedViewer(address viewer, address[] memory viewers) internal pure returns (bool) {
        for (uint i = 0; i < viewers.length; i++) {
            if (viewers[i] == viewer) return true;
        }
        return false;
    }

    function getAllShares() external view returns (bytes32[] memory) {
        return shareIds;
    }
}
