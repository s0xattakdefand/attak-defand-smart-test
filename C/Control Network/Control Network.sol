// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlNetworkHub — A control hub that delegates governance actions to registered network modules
contract ControlNetworkHub {
    address public governor;
    address public pauser;
    address public upgrader;
    address public treasury;

    event ControlRouted(string role, address indexed target);
    event EmergencyPauseTriggered(address indexed by);

    modifier onlyGovernor() {
        require(msg.sender == governor, "Not governor");
        _;
    }

    constructor(address _governor, address _pauser, address _upgrader, address _treasury) {
        governor = _governor;
        pauser = _pauser;
        upgrader = _upgrader;
        treasury = _treasury;
    }

    function routeControl(string calldata role) external view returns (address) {
        if (keccak256(bytes(role)) == keccak256("PAUSER")) return pauser;
        if (keccak256(bytes(role)) == keccak256("UPGRADER")) return upgrader;
        if (keccak256(bytes(role)) == keccak256("TREASURY")) return treasury;
        if (keccak256(bytes(role)) == keccak256("GOVERNOR")) return governor;
        revert("Unknown role");
    }

    function updateControlRoute(string calldata role, address newTarget) external onlyGovernor {
        if (keccak256(bytes(role)) == keccak256("PAUSER")) pauser = newTarget;
        else if (keccak256(bytes(role)) == keccak256("UPGRADER")) upgrader = newTarget;
        else if (keccak256(bytes(role)) == keccak256("TREASURY")) treasury = newTarget;
        else if (keccak256(bytes(role)) == keccak256("GOVERNOR")) governor = newTarget;
        else revert("Unknown role");
        emit ControlRouted(role, newTarget);
    }

    /// ⛔ Emergency function triggered by pauser module
    function emergencyPause() external {
        require(msg.sender == pauser, "Unauthorized");
        emit EmergencyPauseTriggered(msg.sender);
        // Logic to cascade pause to downstream contracts (not shown)
    }
}
