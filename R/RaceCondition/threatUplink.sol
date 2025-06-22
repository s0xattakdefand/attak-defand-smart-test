interface IThreatUplink {
    function logThreat(bytes4 selector, string calldata tag, string calldata message) external;
}

contract RaceAlert {
    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    function reportReentrant(bytes32 hash, address attacker) external {
        uplink.logThreat(bytes4(hash), "ReentrancyRace", string(abi.encodePacked("Reentry detected from: ", toHex(attacker))));
    }

    function toHex(address x) internal pure returns (string memory) {
        bytes memory s = new bytes(42);
        s[0] = '0'; s[1] = 'x';
        for (uint i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint(uint160(x)) / (2**(8*(19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2+i*2] = char(hi); s[3+i*2] = char(lo);
        }
        return string(s);
    }

    function char(bytes1 b) internal pure returns (bytes1) {
        return (uint8(b) < 10) ? bytes1(uint8(b) + 48) : bytes1(uint8(b) + 87);
    }
}
