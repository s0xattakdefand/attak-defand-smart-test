// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentBoundaryRegistry - Define, enforce, and query scope boundaries for Web3 protocol assessments

contract AssessmentBoundaryRegistry {
    address public admin;

    struct BoundaryComponent {
        address component;
        string label;            // e.g., "Vault", "Oracle", "Upgrade Proxy"
        bool inScope;
        string notes;
        uint256 timestamp;
    }

    mapping(bytes32 => BoundaryComponent) public boundaries;
    bytes32[] public boundaryIds;

    event BoundaryDefined(
        bytes32 indexed id,
        address component,
        bool inScope,
        string label
    );

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function defineBoundary(
        address component,
        string calldata label,
        bool inScope,
        string calldata notes
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(component, label, block.timestamp));
        boundaries[id] = BoundaryComponent({
            component: component,
            label: label,
            inScope: inScope,
            notes: notes,
            timestamp: block.timestamp
        });
        boundaryIds.push(id);
        emit BoundaryDefined(id, component, inScope, label);
        return id;
    }

    function isInScope(address component) external view returns (bool) {
        for (uint i = boundaryIds.length; i > 0; i--) {
            bytes32 id = boundaryIds[i - 1];
            if (boundaries[id].component == component) {
                return boundaries[id].inScope;
            }
        }
        return false;
    }

    function getAllBoundaries() external view returns (bytes32[] memory) {
        return boundaryIds;
    }

    function getBoundary(bytes32 id) external view returns (BoundaryComponent memory) {
        return boundaries[id];
    }
}
