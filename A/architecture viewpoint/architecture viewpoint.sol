// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ArchitectureViewpointRegistry - Register structured viewpoints for Web3 architecture clarity

contract ArchitectureViewpointRegistry {
    address public admin;

    struct Viewpoint {
        string role;                 // e.g., "Security", "Developer", "Governance"
        string description;          // Summary of the viewpoint's goal
        string externalReference;    // IPFS/Arweave link to spec or diagram
        bytes32 contentHash;         // keccak256 of viewpoint file (markdown, json)
        address author;
        uint256 timestamp;
    }

    mapping(bytes32 => Viewpoint) public viewpoints;
    bytes32[] public viewpointHistory;

    event ViewpointRegistered(bytes32 indexed id, string role, address indexed author);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerViewpoint(
        string calldata role,
        string calldata description,
        string calldata externalReference,
        bytes32 contentHash
    ) external returns (bytes32 id) {
        id = keccak256(abi.encodePacked(role, description, msg.sender, block.timestamp));
        viewpoints[id] = Viewpoint({
            role: role,
            description: description,
            externalReference: externalReference,
            contentHash: contentHash,
            author: msg.sender,
            timestamp: block.timestamp
        });
        viewpointHistory.push(id);
        emit ViewpointRegistered(id, role, msg.sender);
    }

    function getAllViewpoints() external view returns (bytes32[] memory) {
        return viewpointHistory;
    }

    function getLatestByRole(string calldata role) external view returns (Viewpoint memory) {
        for (uint i = viewpointHistory.length; i > 0; i--) {
            bytes32 id = viewpointHistory[i - 1];
            if (keccak256(bytes(viewpoints[id].role)) == keccak256(bytes(role))) {
                return viewpoints[id];
            }
        }
        revert("No viewpoints for role");
    }
}
