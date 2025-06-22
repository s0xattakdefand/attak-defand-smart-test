contract ReplayForker {
    struct Snapshot {
        bytes4 selector;
        string label;
        uint256 blockHeight;
    }

    mapping(uint256 => Snapshot[]) public driftAtBlock;

    function record(bytes4 sel, string calldata guess) external {
        driftAtBlock[block.number].push(Snapshot(sel, guess, block.number));
    }

    function get(uint256 blockNum) external view returns (Snapshot[] memory) {
        return driftAtBlock[blockNum];
    }
}
