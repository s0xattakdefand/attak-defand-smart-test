// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Root contract acts as the forest — approves and governs child domains.
 */
contract ForestRootRegistry {
    address public rootAdmin;

    struct Domain {
        string name;
        address contractAddress;
        bool verified;
    }

    Domain[] public domains;

    event DomainRegistered(string name, address indexed contractAddress);

    modifier onlyRoot() {
        require(msg.sender == rootAdmin, "Not forest admin");
        _;
    }

    constructor() {
        rootAdmin = msg.sender;
    }

    function registerDomain(string calldata name, address domainAddress) external onlyRoot {
        domains.push(Domain(name, domainAddress, true));
        emit DomainRegistered(name, domainAddress);
    }

    function getDomains() external view returns (Domain[] memory) {
        return domains;
    }
}
