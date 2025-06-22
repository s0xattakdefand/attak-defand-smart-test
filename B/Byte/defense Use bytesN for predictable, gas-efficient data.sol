contract BytesNExample {
    bytes32 public flags;

    function setFlag(bytes32 _flags) public {
        flags = _flags; // ✅ 1 slot, cheaper than dynamic bytes
    }

    function getBit(uint8 i) public view returns (bool) {
        require(i < 256, "Out of range");
        return (flags & (bytes32(uint256(1) << i))) != 0;
    }
}
