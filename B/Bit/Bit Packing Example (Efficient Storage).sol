contract BitPacking {
    // Packed data: 8 bits user type | 248 bits timestamp
    mapping(address => uint256) public packedInfo;

    function setPackedInfo(uint8 userType, uint256 timestamp) public {
        packedInfo[msg.sender] = (uint256(userType) << 248) | timestamp;
    }

    function getUserType(address user) public view returns (uint8) {
        return uint8(packedInfo[user] >> 248);
    }

    function getTimestamp(address user) public view returns (uint256) {
        return packedInfo[user] & ((1 << 248) - 1);
    }
}
