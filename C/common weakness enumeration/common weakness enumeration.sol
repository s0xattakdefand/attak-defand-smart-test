// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CWERegistry {
    address public admin;

    struct CWEEntry {
        string cweId;           // e.g., "CWE-841"
        string name;            // e.g., "Missing Reentrancy Guard"
        string category;        // e.g., "Access Control", "Logic Flaw"
        string description;
        bool active;
        uint256 createdAt;
    }

    mapping(string => CWEEntry) public cweRecords;
    mapping(address => string[]) public contractToCWEs;
    mapping(string => address[]) public cweToContracts;
    string[] public allCWEs;

    event CWECreated(string indexed cweId, string name);
    event CWEContractTagged(string indexed cweId, address indexed contractAddress);
    event CWEDeactivated(string indexed cweId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function createCWE(
        string calldata cweId,
        string calldata name,
        string calldata category,
        string calldata description
    ) external onlyAdmin {
        require(cweRecords[cweId].createdAt == 0, "CWE already exists");

        cweRecords[cweId] = CWEEntry({
            cweId: cweId,
            name: name,
            category: category,
            description: description,
            active: true,
            createdAt: block.timestamp
        });

        allCWEs.push(cweId);
        emit CWECreated(cweId, name);
    }

    function tagContractWithCWE(string calldata cweId, address contractAddr) external onlyAdmin {
        require(cweRecords[cweId].active, "Inactive or not found");

        contractToCWEs[contractAddr].push(cweId);
        cweToContracts[cweId].push(contractAddr);

        emit CWEContractTagged(cweId, contractAddr);
    }

    function deactivateCWE(string calldata cweId) external onlyAdmin {
        require(cweRecords[cweId].createdAt != 0, "Not found");
        cweRecords[cweId].active = false;
        emit CWEDeactivated(cweId);
    }

    function getCWEsForContract(address contractAddr) external view returns (string[] memory) {
        return contractToCWEs[contractAddr];
    }

    function getContractsForCWE(string calldata cweId) external view returns (address[] memory) {
        return cweToContracts[cweId];
    }

    function getCWE(string calldata cweId) external view returns (
        string memory name,
        string memory category,
        string memory description,
        bool active,
        uint256 createdAt
    ) {
        CWEEntry memory c = cweRecords[cweId];
        return (c.name, c.category, c.description, c.active, c.createdAt);
    }

    function getAllCWEIds() external view returns (string[] memory) {
        return allCWEs;
    }
}
