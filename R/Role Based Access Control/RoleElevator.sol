contract RoleElevator {
    mapping(address => uint8) public level;

    function elevate(address who, uint8 newLevel) external {
        require(newLevel > level[who], "Only upgrade");
        level[who] = newLevel;
    }

    function hasAtLeast(address who, uint8 minLevel) external view returns (bool) {
        return level[who] >= minLevel;
    }
}
