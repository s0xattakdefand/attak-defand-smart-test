contract WeightedBIATiers {
    enum Tier { LOW, MEDIUM, HIGH }
    struct Module {
        Tier tier;
        bool down;
        uint256 lastDown;
    }

    mapping(bytes32 => Module) public modules;

    function setModuleTier(bytes32 id, Tier t) external {
        modules[id].tier = t;
    }

    function markDown(bytes32 id) external {
        modules[id].down = true;
        modules[id].lastDown = block.timestamp;
    }

    function getDownModulesByTier(Tier t, bytes32[] calldata modIds)
        external
        view
        returns (bytes32[] memory)
    {
        // collect modules that match the tier & are down
        uint256 count;
        for (uint256 i = 0; i < modIds.length; i++) {
            if (modules[modIds[i]].tier == t && modules[modIds[i]].down) {
                count++;
            }
        }
        bytes32[] memory results = new bytes32[](count);
        uint256 j;
        for (uint256 i = 0; i < modIds.length; i++) {
            if (modules[modIds[i]].tier == t && modules[modIds[i]].down) {
                results[j] = modIds[i];
                j++;
            }
        }
        return results;
    }
}
