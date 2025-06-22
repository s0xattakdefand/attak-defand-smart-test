// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConceptRelationshipRegistry {
    address public admin;

    struct ConceptLink {
        address from;
        address to;
        string relationshipType; // e.g., "admin", "pause", "plugin"
        bool active;
    }

    ConceptLink[] public links;
    mapping(bytes32 => bool) public registeredLinks;

    event RelationshipLinked(address from, address to, string kind);
    event RelationshipRevoked(address from, address to);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function linkConcept(address from, address to, string calldata kind) external onlyAdmin {
        bytes32 hash = keccak256(abi.encodePacked(from, to, kind));
        require(!registeredLinks[hash], "Already linked");

        links.push(ConceptLink(from, to, kind, true));
        registeredLinks[hash] = true;

        emit RelationshipLinked(from, to, kind);
    }

    function revokeLink(address from, address to, string calldata kind) external onlyAdmin {
        bytes32 hash = keccak256(abi.encodePacked(from, to, kind));
        require(registeredLinks[hash], "Link not found");

        for (uint256 i = 0; i < links.length; i++) {
            if (
                links[i].from == from &&
                links[i].to == to &&
                keccak256(bytes(links[i].relationshipType)) == keccak256(bytes(kind))
            ) {
                links[i].active = false;
                break;
            }
        }

        emit RelationshipRevoked(from, to);
    }

    function getAllLinks() external view returns (ConceptLink[] memory) {
        return links;
    }
}
