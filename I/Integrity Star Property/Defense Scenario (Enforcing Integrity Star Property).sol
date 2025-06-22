pragma solidity ^0.8.21;

contract HighIntegrity {
    enum IntegrityLevel { LOW, MEDIUM, HIGH }

    mapping(address => IntegrityLevel) public integrityLevels;
    address public admin;

    bytes public data;

    constructor() {
        admin = msg.sender;
        integrityLevels[admin] = IntegrityLevel.HIGH;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    function setIntegrityLevel(address addr, IntegrityLevel level) external onlyAdmin {
        integrityLevels[addr] = level;
    }

    modifier enforceIntegrity(IntegrityLevel requiredLevel) {
        require(
            integrityLevels[msg.sender] >= requiredLevel,
            "IntegrityStarProperty Violation: Low Integrity Write"
        );
        _;
    }

    function writeData(bytes memory _data) external enforceIntegrity(IntegrityLevel.HIGH) {
        data = _data;
    }
}
