contract AutoWeightBIA {
    struct BIARecord {
        uint256 usage;
        uint8 impact;
    }

    mapping(bytes32 => BIARecord) public modules;

    function updateUsage(bytes32 id, uint256 newUsage) external {
        modules[id].usage = newUsage;
        modules[id].impact = _calcImpact(newUsage); // auto
    }

    function _calcImpact(uint256 usage) internal pure returns (uint8) {
        if (usage > 1e24) return 100;   // e.g. extremely critical
        if (usage > 1e20) return 80; 
        if (usage > 1e16) return 50;
        return 10;
    }
}
