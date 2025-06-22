contract FallbackSpam {
    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    fallback() external payable {
        uplink.logThreat("FallbackSpam", "Selector drift", gasleft());
    }
}
