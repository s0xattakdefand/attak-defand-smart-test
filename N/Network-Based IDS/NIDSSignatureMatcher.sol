contract NIDSSignatureMatcher {
    mapping(bytes4 => string) public knownCVEs;
    address public threatUplink;

    constructor(address _uplink) {
        threatUplink = _uplink;
    }

    function addCVE(bytes4 selector, string calldata cve) external {
        knownCVEs[selector] = cve;
    }

    function scan(bytes4 selector) external {
        if (bytes(knownCVEs[selector]).length > 0) {
            ThreatUplink(threatUplink).logThreat(selector, "CVE", knownCVEs[selector]);
        }
    }
}
