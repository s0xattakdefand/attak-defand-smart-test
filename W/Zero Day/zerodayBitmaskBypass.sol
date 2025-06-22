contract ZeroDayBitmaskBypass {
    mapping(address => uint8) public permissions;

    modifier onlyAdmin() {
        require((permissions[msg.sender] & 0xF0) == 0xF0, "Admin access required");
        _;
    }

    function setPermission(address user, uint8 mask) external {
        permissions[user] = mask;
    }

    function adminAction() external onlyAdmin {
        // 🔥 Bitmask 0xFF or 0xF1 may pass unnoticed if not enforced strictly
    }
}
