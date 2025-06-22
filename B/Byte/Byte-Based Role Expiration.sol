contract ByteRoleExpiry {
    struct RoleInfo {
        bytes1 roles; // bitfield: bit 0 = Admin, 1 = Minter, etc.
        uint256 expiry;
    }

    mapping(address => RoleInfo) public userRoles;

    function assignRole(address user, uint8 bit, uint256 duration) external {
        userRoles[user].roles |= bytes1(uint8(1 << bit));
        userRoles[user].expiry = block.timestamp + duration;
    }

    function hasRole(address user, uint8 bit) public view returns (bool) {
        if (block.timestamp > userRoles[user].expiry) return false;
        return (userRoles[user].roles & bytes1(uint8(1 << bit))) != 0;
    }
}
