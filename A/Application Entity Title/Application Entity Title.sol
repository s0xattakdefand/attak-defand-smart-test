// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AETRegistry — Application Entity Title Identifier Registry for Web3
contract AETRegistry {
    address public admin;

    struct AET {
        string title;          // e.g., "DICOM_NODE_A", "zkRelay::MetaTx"
        string uri;            // IPFS, HTTPS, or DNS reference
        address owner;
        bool active;
        uint256 registeredAt;
    }

    mapping(bytes32 => AET) public aets;
    mapping(address => bytes32[]) public ownerAETs;

    event AETRegistered(bytes32 indexed id, string title, address indexed owner);
    event AETDeactivated(bytes32 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAET(string calldata title, string calldata uri) external returns (bytes32) {
        bytes32 id = keccak256(abi.encodePacked(msg.sender, title, block.timestamp));
        require(aets[id].registeredAt == 0, "Already registered");

        aets[id] = AET(title, uri, msg.sender, true, block.timestamp);
        ownerAETs[msg.sender].push(id);

        emit AETRegistered(id, title, msg.sender);
        return id;
    }

    function deactivateAET(bytes32 id) external {
        require(aets[id].owner == msg.sender || msg.sender == admin, "Unauthorized");
        aets[id].active = false;
        emit AETDeactivated(id);
    }

    function getAET(bytes32 id) external view returns (AET memory) {
        return aets[id];
    }

    function getOwnerAETs(address owner) external view returns (bytes32[] memory) {
        return ownerAETs[owner];
    }

    function isAETActive(bytes32 id) external view returns (bool) {
        return aets[id].active;
    }
}
