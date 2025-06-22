contract StorageCellSlot {
    // each var uses 1 storage cell (slot) if separate
    uint256 public cellA;
    uint256 public cellB;

    function writeCellA(uint256 val) public {
        cellA = val; // writes slot #0
    }

    function writeCellB(uint256 val) public {
        cellB = val; // writes slot #1
    }
}
