// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ASNRegistry - On-chain Autonomous System Number registry for decentralized networks

contract ASNRegistry {
    address public admin;

    struct ASN {
        uint256 number;
        address owner;
        string domainName;
        string description;
        bool isActive;
    }

    mapping(uint256 => ASN) public registry;
    mapping(address => uint256) public asnOf;
    uint256 public nextASN = 64512; // Private ASN range start

    event ASNRegistered(uint256 indexed asn, address indexed owner, string domain);
    event ASNDeactivated(uint256 indexed asn);
    event ASNReactivated(uint256 indexed asn);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyASNOwner(uint256 asn) {
        require(registry[asn].owner == msg.sender, "Not ASN owner");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerASN(string calldata domainName, string calldata description) external returns (uint256) {
        require(asnOf[msg.sender] == 0, "Already owns ASN");

        uint256 asn = nextASN++;
        registry[asn] = ASN({
            number: asn,
            owner: msg.sender,
            domainName: domainName,
            description: description,
            isActive: true
        });

        asnOf[msg.sender] = asn;
        emit ASNRegistered(asn, msg.sender, domainName);
        return asn;
    }

    function deactivateASN(uint256 asn) external onlyASNOwner(asn) {
        registry[asn].isActive = false;
        emit ASNDeactivated(asn);
    }

    function reactivateASN(uint256 asn) external onlyASNOwner(asn) {
        registry[asn].isActive = true;
        emit ASNReactivated(asn);
    }

    function getASN(address operator) external view returns (ASN memory) {
        return registry[asnOf[operator]];
    }

    function isASNActive(uint256 asn) external view returns (bool) {
        return registry[asn].isActive;
    }
}
