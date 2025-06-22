interface IThreatUplink {
    function logThreat(bytes4 selector, string calldata tag, string calldata message) external;
}

contract ZeroDayTelemetryHook {
    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function report(bytes4 selector) external {
        uplink.logThreat(selector, "ZeroDay", "First-seen selector. May indicate unknown entrypoint.");
    }
}
