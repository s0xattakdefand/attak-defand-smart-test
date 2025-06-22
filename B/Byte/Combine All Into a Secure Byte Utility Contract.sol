contract ByteSecurityKit {
    bytes32 public storageFlags;
    bytes4[3] public secureArray;
    mapping(address => bytes1) public perms;

    // Bitwise toggle
    function toggleBit(uint8 i) public {
        require(i < 256);
        storageFlags ^= bytes32(uint256(1) << i);
    }

    // Safe array set
    function setArray(uint index, bytes4 val) public {
        require(index < secureArray.length, "Overflow");
        secureArray[index] = val;
    }

    // Bytes1 Access Control
    function grantPerm(address user, uint8 b) public {
        perms[user] |= bytes1(uint8(1 << b));
    }

    function hasPerm(address user, uint8 b) public view returns (bool) {
        return (perms[user] & bytes1(uint8(1 << b))) != 0;
    }
}
