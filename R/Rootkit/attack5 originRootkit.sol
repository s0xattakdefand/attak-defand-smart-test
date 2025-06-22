contract OriginPoison {
    address public root = 0x123...;

    function rootOnly() external {
        require(tx.origin == root, "Spoofed origin");
        // dangerous
    }
}
