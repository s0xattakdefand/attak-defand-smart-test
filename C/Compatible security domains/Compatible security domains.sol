// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CompatibleDomainRegistry {
    address public admin;

    struct Domain {
        uint32 domainId;
        address gateway;         // Verified sender/bridge/relayer
        string name;             // e.g., "Ethereum", "Arbitrum", "zkSync"
        bool active;
        uint256 registeredAt;
    }

    mapping(uint32 => Domain) public domains;
    uint32[] public domainList;

    event DomainRegistered(uint32 indexed domainId, string name, address gateway);
    event DomainDeactivated(uint32 indexed domainId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerDomain(uint32 domainId, string calldata name, address gateway) external onlyAdmin {
        require(domains[domainId].registeredAt == 0, "Already registered");

        domains[domainId] = Domain({
            domainId: domainId,
            gateway: gateway,
            name: name,
            active: true,
            registeredAt: block.timestamp
        });

        domainList.push(domainId);
        emit DomainRegistered(domainId, name, gateway);
    }

    function deactivateDomain(uint32 domainId) external onlyAdmin {
        require(domains[domainId].active, "Already inactive");
        domains[domainId].active = false;
        emit DomainDeactivated(domainId);
    }

    function isCompatible(uint32 domainId, address caller) external view returns (bool) {
        Domain memory d = domains[domainId];
        return d.active && d.gateway == caller;
    }

    function getDomain(uint32 domainId) external view returns (string memory, address, bool) {
        Domain memory d = domains[domainId];
        return (d.name, d.gateway, d.active);
    }

    function getAllDomains() external view returns (uint32[] memory) {
        return domainList;
    }
}
