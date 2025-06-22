contract BytePermissions {
    mapping(address => bytes1) public permissions;

    // Bit 0: Transfer, Bit 1: Mint, Bit 2: Burn
    function grant(address user, uint8 bit) public {
        permissions[user] |= bytes1(uint8(1 << bit));
    }

    function revoke(address user, uint8 bit) public {
        permissions[user] &= ~bytes1(uint8(1 << bit));
    }

    function can(address user, uint8 bit) public view returns (bool) {
        return (permissions[user] & bytes1(uint8(1 << bit))) != 0;
    }
}
