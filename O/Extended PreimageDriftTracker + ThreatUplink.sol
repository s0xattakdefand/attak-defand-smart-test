interface IThreatUplink {
    function logThreat(bytes4 selector, string calldata tag, string calldata message) external;
}

contract PreimageDriftTracker {
    mapping(bytes32 => uint256) public usage;
    mapping(bytes32 => address[]) public users;

    IThreatUplink public uplink;

    constructor(address _uplink) {
        uplink = IThreatUplink(_uplink);
    }

    event Drift(bytes32 indexed hash, address indexed user, uint256 count);

    function track(string calldata preimage) external {
        bytes32 hash = keccak256(abi.encodePacked(preimage));
        usage[hash]++;
        users[hash].push(msg.sender);

        if (usage[hash] > 1) {
            uplink.logThreat(
                bytes4(hash),
                "PreimageReplay",
                string(abi.encodePacked("Hash reused by ", toAscii(msg.sender)))
            );
        }

        emit Drift(hash, msg.sender, usage[hash]);
    }

    function toAscii(address x) internal pure returns (string memory) {
        bytes memory s = new bytes(42);
        s[0] = '0';
        s[1] = 'x';
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint(uint160(x)) / (2**(8*(19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2 + i * 2] = char(hi);
            s[3 + i * 2] = char(lo);
        }
        return string(s);
    }

    function char(bytes1 b) internal pure returns (bytes1) {
        return (uint8(b) < 10) ? bytes1(uint8(b) + 48) : bytes1(uint8(b) + 87);
    }
}
