contract EventFlood {
    event MassiveLog(uint256 i, address indexed sender);

    IThreatUplink public uplink;
    uint256 public total;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function flood(uint256 count) external {
        require(count <= 1000, "Too many logs");
        for (uint256 i = 0; i < count; ++i) {
            emit MassiveLog(i, msg.sender);
        }
        total += count;
        uplink.logThreat("EventFlood", "Event spam triggered", count);
    }
}
