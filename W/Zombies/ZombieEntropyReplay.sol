interface IThreatUplink {
    function logThreat(bytes4 selector, string calldata tag, string calldata msg) external;
}

contract ZombieThreatRelay {
    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function report(bytes4 sel, string calldata context) external {
        uplink.logThreat(sel, "ZombieActivity", context);
    }
}
