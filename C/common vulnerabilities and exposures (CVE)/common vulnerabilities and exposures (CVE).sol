// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CVERegistry {
    address public admin;

    struct CVE {
        string cveId;            // e.g. "CVE-2022-12345"
        string title;
        string description;
        uint256 createdAt;
        bool active;
    }

    mapping(string => CVE) public cves;                     // cveId => CVE
    mapping(address => string[]) public affectedContracts;  // contract => CVE IDs
    mapping(string => address[]) public cveAffectedList;    // CVE ID => affected contracts

    event CVEReported(string indexed cveId, string title);
    event ContractTagged(address indexed contractAddr, string indexed cveId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function reportCVE(
        string calldata cveId,
        string calldata title,
        string calldata description
    ) external onlyAdmin {
        require(cves[cveId].createdAt == 0, "Already exists");

        cves[cveId] = CVE({
            cveId: cveId,
            title: title,
            description: description,
            createdAt: block.timestamp,
            active: true
        });

        emit CVEReported(cveId, title);
    }

    function tagContract(string calldata cveId, address contractAddr) external onlyAdmin {
        require(cves[cveId].createdAt != 0, "CVE not found");

        affectedContracts[contractAddr].push(cveId);
        cveAffectedList[cveId].push(contractAddr);

        emit ContractTagged(contractAddr, cveId);
    }

    function getCVE(string calldata cveId) external view returns (
        string memory, string memory, string memory, uint256, bool
    ) {
        CVE memory c = cves[cveId];
        return (c.cveId, c.title, c.description, c.createdAt, c.active);
    }

    function getCVEsByContract(address contractAddr) external view returns (string[] memory) {
        return affectedContracts[contractAddr];
    }

    function getContractsByCVE(string calldata cveId) external view returns (address[] memory) {
        return cveAffectedList[cveId];
    }

    function deactivateCVE(string calldata cveId) external onlyAdmin {
        cves[cveId].active = false;
    }
}
