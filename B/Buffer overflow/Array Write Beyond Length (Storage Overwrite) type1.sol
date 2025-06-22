contract StorageOverflow {
    uint256 public a = 1;
    uint256[] public buffer;

    function overflow() public {
        assembly {
            sstore(add(buffer.slot, 1), 999) // force overwrite next slot
        }
    }
}
