contract ReplayForker {
    struct ABITrace {
        bytes4 selector;
        string name;
        uint256 blockNumber;
    }

    mapping(uint256 => ABITrace[]) public atBlock;

    function record(bytes4 sel, string calldata name) external {
        atBlock[block.number].push(ABITrace(sel, name, block.number));
    }
}
