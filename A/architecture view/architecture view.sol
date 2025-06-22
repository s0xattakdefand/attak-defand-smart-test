// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ArchitectureViewRegistry - Register versioned architecture views on-chain

contract ArchitectureViewRegistry {
    address public admin;

    struct ViewMetadata {
        string viewType;           // e.g., "Component", "Upgrade", "Execution"
        string description;        // Markdown or short summary
        string externalDiagramURL; // IPFS/Arweave diagram URL
        bytes32 contentHash;       // keccak256 hash of full JSON/Markdown spec
        uint256 timestamp;
    }

    mapping(bytes32 => ViewMetadata) public views;
    bytes32[] public viewHistory;

    event ArchitectureViewAdded(bytes32 indexed viewId, string viewType, string description);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addView(
        string calldata viewType,
        string calldata description,
        string calldata diagramURL,
        bytes32 contentHash
    ) external onlyAdmin returns (bytes32 viewId) {
        viewId = keccak256(abi.encodePacked(viewType, diagramURL, block.timestamp));
        views[viewId] = ViewMetadata({
            viewType: viewType,
            description: description,
            externalDiagramURL: diagramURL,
            contentHash: contentHash,
            timestamp: block.timestamp
        });

        viewHistory.push(viewId);
        emit ArchitectureViewAdded(viewId, viewType, description);
    }

    function getLatestView() external view returns (ViewMetadata memory) {
        require(viewHistory.length > 0, "No views recorded");
        return views[viewHistory[viewHistory.length - 1]];
    }

    function getViewCount() external view returns (uint256) {
        return viewHistory.length;
    }
}
