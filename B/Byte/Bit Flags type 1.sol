contract BitFlags {
    bytes1 public permissions; // 8 flags

    function enable(uint8 i) external {
        require(i < 8, "Invalid bit");
        permissions |= bytes1(uint8(1 << i));
    }

    function disable(uint8 i) external {
        require(i < 8, "Invalid bit");
        permissions &= ~bytes1(uint8(1 << i));
    }

    function check(uint8 i) external view returns (bool) {
        return (permissions & bytes1(uint8(1 << i))) != 0;
    }
}
