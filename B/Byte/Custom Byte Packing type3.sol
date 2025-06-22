contract PackedData {
    bytes32 public packed;

    // Encodes 4 uint8 values into 32-byte slot
    function encode(uint8 a, uint8 b, uint8 c, uint8 d) public {
        packed = bytes32((uint256(a) << 24) | (uint256(b) << 16) | (uint256(c) << 8) | d);
    }

    function decode() public view returns (uint8, uint8, uint8, uint8) {
        uint256 raw = uint256(packed);
        return (
            uint8((raw >> 24) & 0xFF),
            uint8((raw >> 16) & 0xFF),
            uint8((raw >> 8) & 0xFF),
            uint8(raw & 0xFF)
        );
    }
}
