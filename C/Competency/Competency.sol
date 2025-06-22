// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CompetencyRegistry {
    address public admin;

    enum Level { None, Basic, Verified, Trusted, Critical }

    struct Competency {
        string domain;      // e.g., "VaultOperator", "DAOProposal", "ZKVerifier"
        Level level;
        uint256 timestamp;
    }

    mapping(address => mapping(string => Competency)) public competencies;
    mapping(string => address[]) public domainActors;

    event CompetencyGranted(address indexed actor, string domain, Level level);
    event CompetencyRevoked(address indexed actor, string domain);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function grantCompetency(address actor, string calldata domain, Level level) external onlyAdmin {
        competencies[actor][domain] = Competency(domain, level, block.timestamp);
        domainActors[domain].push(actor);
        emit CompetencyGranted(actor, domain, level);
    }

    function revokeCompetency(address actor, string calldata domain) external onlyAdmin {
        delete competencies[actor][domain];
        emit CompetencyRevoked(actor, domain);
    }

    function getCompetency(address actor, string calldata domain) external view returns (Level, uint256) {
        Competency memory c = competencies[actor][domain];
        return (c.level, c.timestamp);
    }

    function hasLevel(address actor, string calldata domain, Level required) external view returns (bool) {
        return uint(competencies[actor][domain].level) >= uint(required);
    }
}
