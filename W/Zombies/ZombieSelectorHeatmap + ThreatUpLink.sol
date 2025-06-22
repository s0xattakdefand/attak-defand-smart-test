interface IThreatUplink {
    function logThreat(bytes4 selector, string calldata tag, string calldata message) external;
}

contract ZombieSelectorHeatmapWithAlert is ZombieSelectorHeatmap {
    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function log(bytes4 selector) public override {
        super.log(selector);
        if (selectorHits[selector].count > 3) {
            uplink.logThreat(selector, "ZombieSelectorEntropy", "High-drift selector hit repeatedly");
        }
    }
}
