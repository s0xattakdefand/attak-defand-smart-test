contract ByteSafeArray {
    bytes4[3] public fixedBytes; // exactly 3 slots of 4-byte values

    function write(uint256 index, bytes4 val) public {
        require(index < fixedBytes.length, "Out of bounds"); // ✅ overflow guard
        fixedBytes[index] = val;
    }

    function read(uint256 index) public view returns (bytes4) {
        require(index < fixedBytes.length, "Out of bounds");
        return fixedBytes[index];
    }
}
