// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CVEIdentifierRegistry {
    address public admin;

    struct CVE {
        string id;             // e.g., "CVE-2023-12345"
        string title;
        string description;
        uint256 publishedAt;
        bool active;
    }

    mapping(string => CVE) public cves;                 // CVE ID => metadata
    mapping(address => string[]) public contractToCVEs; // Contract => CVEs affecting it
    mapping(string => address[]) public cveToContracts; // CVE => affected contracts

    event CVEDeclared(string indexed id, string title);
    event CVETagged(string indexed id, address indexed contractAddress);
    event CVEDeactivated(string indexed id);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function declareCVE(
        string calldata id,
        string calldata title,
        string calldata description
    ) external onlyAdmin {
        require(cves[id].publishedAt == 0, "CVE already exists");

        cves[id] = CVE({
            id: id,
            title: title,
            description: description,
            publishedAt: block.timestamp,
            active: true
        });

        emit CVEDeclared(id, title);
    }

    function tagContract(string calldata id, address contractAddr) external onlyAdmin {
        require(cves[id].active, "CVE not active");

        contractToCVEs[contractAddr].push(id);
        cveToContracts[id].push(contractAddr);

        emit CVETagged(id, contractAddr);
    }

    function deactivateCVE(string calldata id) external onlyAdmin {
        cves[id].active = false;
        emit CVEDeactivated(id);
    }

    function getCVEsByContract(address contractAddr) external view returns (string[] memory) {
        return contractToCVEs[contractAddr];
    }

    function getContractsByCVE(string calldata id) external view returns (address[] memory) {
        return cveToContracts[id];
    }

    function isActive(string calldata id) external view returns (bool) {
        return cves[id].active;
    }

    function getCVE(string calldata id) external view returns (
        string memory title,
        string memory description,
        uint256 publishedAt,
        bool active
    ) {
        CVE memory c = cves[id];
        return (c.title, c.description, c.publishedAt, c.active);
    }
}
