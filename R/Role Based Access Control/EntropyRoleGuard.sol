contract EntropyRoleGuard {
    mapping(address => string) public role;
    uint8 public entropyLimit = 6;

    function assign(address user, string calldata r) external {
        require(selectorEntropy(msg.sig) <= entropyLimit, "High entropy call");
        role[user] = r;
    }

    function selectorEntropy(bytes4 sel) internal pure returns (uint8 e) {
        uint32 x = uint32(sel);
        while (x != 0) { e++; x &= (x - 1); }
    }
}
