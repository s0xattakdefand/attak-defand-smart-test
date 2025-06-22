// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CompetencyAreaRegistry {
    address public admin;

    enum Level { None, Contributor, Operator, Maintainer, Root }

    struct Competency {
        string area;       // e.g., "VaultOps", "Governance", "zkProofs"
        Level level;
        uint256 grantedAt;
    }

    mapping(address => mapping(string => Competency)) public registry;
    mapping(string => address[]) public areaMembers;

    event CompetencyAssigned(address indexed actor, string area, Level level);
    event CompetencyRevoked(address indexed actor, string area);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function assign(address actor, string calldata area, Level level) external onlyAdmin {
        registry[actor][area] = Competency(area, level, block.timestamp);
        areaMembers[area].push(actor);
        emit CompetencyAssigned(actor, area, level);
    }

    function revoke(address actor, string calldata area) external onlyAdmin {
        delete registry[actor][area];
        emit CompetencyRevoked(actor, area);
    }

    function getLevel(address actor, string calldata area) external view returns (Level) {
        return registry[actor][area].level;
    }

    function hasMinimumLevel(address actor, string calldata area, Level required) external view returns (bool) {
        return uint(registry[actor][area].level) >= uint(required);
    }

    function getAreaMembers(string calldata area) external view returns (address[] memory) {
        return areaMembers[area];
    }
}
