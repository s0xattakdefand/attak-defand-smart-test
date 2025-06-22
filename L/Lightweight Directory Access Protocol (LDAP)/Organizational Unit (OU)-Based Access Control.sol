pragma solidity ^0.8.21;

contract OUAccessControl {
    mapping(address => string) public unit;

    modifier onlyUnit(string memory requiredUnit) {
        require(
            keccak256(bytes(unit[msg.sender])) == keccak256(bytes(requiredUnit)),
            "Access denied"
        );
        _;
    }

    function setUnit(string memory name) external {
        unit[msg.sender] = name;
    }

    function accessHRSystem() external onlyUnit("HR") {
        // HR-only access logic
    }
}
