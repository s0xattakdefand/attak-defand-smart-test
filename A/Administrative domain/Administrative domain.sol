// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Administrative Domain Registry
contract AdminDomainManager {
    struct Domain {
        address admin;
        string label;
        mapping(address => bool) members;
        bool exists;
    }

    mapping(bytes32 => Domain) private domains;
    mapping(bytes32 => address[]) private domainMembers;

    event DomainCreated(bytes32 indexed id, address admin, string label);
    event MemberAdded(bytes32 indexed id, address member);
    event MemberRemoved(bytes32 indexed id, address member);

    modifier onlyDomainAdmin(bytes32 domainId) {
        require(domains[domainId].admin == msg.sender, "Not domain admin");
        _;
    }

    modifier onlyDomainMember(bytes32 domainId) {
        require(domains[domainId].members[msg.sender], "Not domain member");
        _;
    }

    function createDomain(string calldata label) external returns (bytes32 domainId) {
        domainId = keccak256(abi.encodePacked(label, msg.sender));
        require(!domains[domainId].exists, "Domain exists");

        domains[domainId].admin = msg.sender;
        domains[domainId].label = label;
        domains[domainId].members[msg.sender] = true;
        domains[domainId].exists = true;
        domainMembers[domainId].push(msg.sender);

        emit DomainCreated(domainId, msg.sender, label);
    }

    function addMember(bytes32 domainId, address member) external onlyDomainAdmin(domainId) {
        domains[domainId].members[member] = true;
        domainMembers[domainId].push(member);
        emit MemberAdded(domainId, member);
    }

    function removeMember(bytes32 domainId, address member) external onlyDomainAdmin(domainId) {
        domains[domainId].members[member] = false;
        emit MemberRemoved(domainId, member);
    }

    function isMember(bytes32 domainId, address user) external view returns (bool) {
        return domains[domainId].members[user];
    }

    function getAdmin(bytes32 domainId) external view returns (address) {
        return domains[domainId].admin;
    }

    function getLabel(bytes32 domainId) external view returns (string memory) {
        return domains[domainId].label;
    }

    function getMembers(bytes32 domainId) external view returns (address[] memory) {
        return domainMembers[domainId];
    }
}
