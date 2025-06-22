// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlParameterManager — Manages and enforces critical protocol parameters
contract ControlParameterManager {
    address public owner;

    struct Parameter {
        string label;
        uint256 value;
        uint256 min;
        uint256 max;
    }

    mapping(bytes32 => Parameter) public controlParameters;

    event ParameterSet(string label, uint256 newValue);
    event ParameterBoundsUpdated(string label, uint256 min, uint256 max);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;

        // Initialize core control parameters
        _setInitial("MAX_WITHDRAW", 1 ether, 0.1 ether, 10 ether);
        _setInitial("RISK_THRESHOLD", 100, 10, 500);
        _setInitial("ACTION_COOLDOWN", 300, 60, 3600); // 5 min default
    }

    function _setInitial(string memory label, uint256 value, uint256 min, uint256 max) internal {
        bytes32 id = keccak256(abi.encodePacked(label));
        controlParameters[id] = Parameter(label, value, min, max);
    }

    /// 🔧 Update control parameter within its bounds
    function setParameter(string calldata label, uint256 newValue) external onlyOwner {
        bytes32 id = keccak256(abi.encodePacked(label));
        Parameter storage param = controlParameters[id];
        require(newValue >= param.min && newValue <= param.max, "Value out of bounds");
        param.value = newValue;
        emit ParameterSet(label, newValue);
    }

    /// 🛡️ Adjust parameter bounds
    function setBounds(string calldata label, uint256 newMin, uint256 newMax) external onlyOwner {
        bytes32 id = keccak256(abi.encodePacked(label));
        controlParameters[id].min = newMin;
        controlParameters[id].max = newMax;
        emit ParameterBoundsUpdated(label, newMin, newMax);
    }

    /// 🔍 Read parameter value
    function get(string calldata label) external view returns (uint256) {
        return controlParameters[keccak256(abi.encodePacked(label))].value;
    }

    /// ✅ Example enforcement
    function withdraw(uint256 amount) external {
        uint256 max = controlParameters[keccak256(abi.encodePacked("MAX_WITHDRAW"))].value;
        require(amount <= max, "Exceeds max withdraw");
        // Withdraw logic...
    }
}
