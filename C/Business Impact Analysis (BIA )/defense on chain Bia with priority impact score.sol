// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * On-chain BIA approach:
 * - Each module has an impact score + downtime cost
 * - The protocol can quickly see which module is critical to fix
 */
contract BIADefense {
    struct ModuleInfo {
        string name;
        bool operational;
        uint8 impactScore;    // e.g., 1-100 (the higher, the more critical)
        uint256 lastDowntime; // timestamp module went down
    }

    mapping(bytes32 => ModuleInfo) public modules;

    // Example: sum of all critical modules' downtime cost for quick BIA analysis
    uint256 public totalDowntimeCost;

    event ModuleRegistered(bytes32 indexed id, string name, uint8 impactScore);
    event ModuleDown(bytes32 indexed id, uint256 time);
    event ModuleUp(bytes32 indexed id, uint256 time);

    // Register a module with an ID, name, and impact score
    function registerModule(
        bytes32 id,
        string calldata name,
        uint8 impactScore
    ) external {
        // In production, only admin or governance can do this
        modules[id] = ModuleInfo(name, true, impactScore, 0);
        emit ModuleRegistered(id, name, impactScore);
    }

    function markModuleDown(bytes32 id) external {
        ModuleInfo storage m = modules[id];
        require(m.operational, "Already down");
        m.operational = false;
        m.lastDowntime = block.timestamp;
        emit ModuleDown(id, block.timestamp);
    }

    function markModuleUp(bytes32 id) external {
        ModuleInfo storage m = modules[id];
        require(!m.operational, "Already up");

        // Calculate downtime cost: (timeDown * impactScore)
        uint256 timeDown = block.timestamp - m.lastDowntime;
        uint256 cost = timeDown * m.impactScore; 
        totalDowntimeCost += cost;

        m.operational = true;
        m.lastDowntime = 0;

        emit ModuleUp(id, block.timestamp);
    }

    function getDowntimeCost(bytes32 id) public view returns (uint256) {
        // If module is still down, estimate cost up to now
        ModuleInfo memory m = modules[id];
        if (m.operational) {
            return 0;
        }
        uint256 timeDown = block.timestamp - m.lastDowntime;
        return timeDown * m.impactScore;
    }

    // Quick check: which module is highest impact + down
    function highestPriorityDownModule(bytes32[] calldata moduleIds) 
        external 
        view 
        returns (bytes32 highestId, uint256 bestScore)
    {
        // find the module with greatest impactScore that is down
        // a simple loop approach
        for (uint256 i = 0; i < moduleIds.length; i++) {
            ModuleInfo memory mod = modules[moduleIds[i]];
            if (!mod.operational && mod.impactScore > bestScore) {
                bestScore = mod.impactScore;
                highestId = moduleIds[i];
            }
        }
    }
}
