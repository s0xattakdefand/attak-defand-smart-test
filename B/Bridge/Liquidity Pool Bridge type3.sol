contract LiquidityBridge {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function bridgeOut(uint256 amount) public {
        token.transferFrom(msg.sender, address(this), amount);
    }

    function bridgeIn(address user, uint256 amount) public {
        // Assume external relayer verifies off-chain proof
        token.transfer(user, amount);
    }

    function addLiquidity(uint256 amount) public {
        token.transferFrom(msg.sender, address(this), amount);
    }
}
