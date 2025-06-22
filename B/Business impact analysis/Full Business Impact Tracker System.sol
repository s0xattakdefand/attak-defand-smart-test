// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BusinessImpactTracker {
    enum Criticality { Low, Medium, High }

    struct ModuleStatus {
        string name;
        bool isActive;
        uint256 lastDowntimeStart;
        uint256 totalDowntime;
        uint256 lossPerHourInETH;
        Criticality level;
    }

    address public owner;
    uint256 public ethLossSimulated;

    mapping(bytes32 => ModuleStatus) public modules;

    event ModulePaused(bytes32 indexed id, string name, uint256 timestamp);
    event ModuleResumed(bytes32 indexed id, string name, uint256 downtime, uint256 simulatedLoss);
    event ModuleUpdated(bytes32 indexed id, string name);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerModule(
        bytes32 id,
        string calldata name,
        uint256 lossPerHour,
        Criticality level
    ) public onlyOwner {
        modules[id] = ModuleStatus({
            name: name,
            isActive: true,
            lastDowntimeStart: 0,
            totalDowntime: 0,
            lossPerHourInETH: lossPerHour,
            level: level
        });
        emit ModuleUpdated(id, name);
    }

    function pauseModule(bytes32 id) external onlyOwner {
        ModuleStatus storage m = modules[id];
        require(m.isActive, "Already paused");
        m.isActive = false;
        m.lastDowntimeStart = block.timestamp;
        emit ModulePaused(id, m.name, block.timestamp);
    }

    function resumeModule(bytes32 id) external onlyOwner {
        ModuleStatus storage m = modules[id];
        require(!m.isActive, "Not paused");
        uint256 downtime = block.timestamp - m.lastDowntimeStart;
        uint256 simulatedLoss = (downtime * m.lossPerHourInETH) / 3600;

        m.totalDowntime += downtime;
        m.isActive = true;
        m.lastDowntimeStart = 0;
        ethLossSimulated += simulatedLoss;

        emit ModuleResumed(id, m.name, downtime, simulatedLoss);
    }

    function getModuleImpact(bytes32 id) external view returns (
        string memory name,
        Criticality level,
        uint256 totalDowntime,
        uint256 lossPerHour,
        bool isActive
    ) {
        ModuleStatus storage m = modules[id];
        return (m.name, m.level, m.totalDowntime, m.lossPerHourInETH, m.isActive);
    }
}
