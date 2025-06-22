contract DepthBomb {
    IThreatUplink public uplink;
    uint256 public depth;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function recurse(uint256 max) external {
        if (depth < max) {
            depth++;
            this.recurse(max);
        }
        uplink.logThreat("DepthBomb", "Reentry depth reached", depth);
    }
}
