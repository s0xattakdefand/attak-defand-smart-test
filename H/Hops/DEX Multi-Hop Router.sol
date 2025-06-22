interface IToken {
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract MultiHopDEX {
    function multiHopSwap(address[] calldata path, uint256 amountIn) external {
        require(path.length >= 2, "Too short");

        IToken(path[0]).transferFrom(msg.sender, path[1], amountIn); // Hop 1

        for (uint i = 1; i < path.length - 1; i++) {
            // Fake swap simulation (in real case, AMMs are used)
            IToken(path[i]).transferFrom(path[i], path[i + 1], amountIn); // Hop 2+
        }

        // Final output is in path[path.length - 1]
    }
}
