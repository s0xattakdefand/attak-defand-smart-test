// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CSRCRegistry {
    address public admin;

    struct Resource {
        string name;
        string category;
        string ipfsHash; // Off-chain file reference (e.g., audit template or SimStrategy bundle)
        address contributor;
        bool active;
        uint256 timestamp;
    }

    Resource[] public resources;
    mapping(bytes32 => bool) public registeredHashes;

    event ResourceAdded(uint256 id, string name, string category, address indexed contributor);
    event ResourceRevoked(uint256 id, address indexed by);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addResource(string calldata name, string calldata category, string calldata ipfsHash) external returns (uint256 id) {
        bytes32 hashKey = keccak256(abi.encodePacked(name, category, ipfsHash));
        require(!registeredHashes[hashKey], "Already exists");

        id = resources.length;
        resources.push(Resource({
            name: name,
            category: category,
            ipfsHash: ipfsHash,
            contributor: msg.sender,
            active: true,
            timestamp: block.timestamp
        }));

        registeredHashes[hashKey] = true;
        emit ResourceAdded(id, name, category, msg.sender);
    }

    function revokeResource(uint256 id) external onlyAdmin {
        resources[id].active = false;
        emit ResourceRevoked(id, msg.sender);
    }

    function getResource(uint256 id) external view returns (Resource memory) {
        return resources[id];
    }

    function totalResources() external view returns (uint256) {
        return resources.length;
    }
}
