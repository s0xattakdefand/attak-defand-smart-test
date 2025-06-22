// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract OpenSourceRegistry {
    struct Project {
        string name;
        string license;
        string sourceURI; // e.g., IPFS/GitHub
    }

    mapping(address => Project) public projects;

    function register(string calldata name, string calldata license, string calldata sourceURI) external {
        projects[msg.sender] = Project(name, license, sourceURI);
    }

    function getProject(address dev) external view returns (Project memory) {
        return projects[dev];
    }
}
