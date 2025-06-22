contract MultiChainPrimary {
    address public admin;
    address public altChainMirror; // address on another chain (like Polygon, BSC)

    function updateBalance(address user, uint256 newBal) external {
        // normal logic
        // also do cross-chain message or bridging to altChainMirror if possible
    }
}
