contract HoneymonkeySellTrap {
    event SellBlocked(address token, string reason);
    event SellPassed(address token);

    function simulateSell(address token, uint256 amount) external {
        try IERC20(token).transfer(msg.sender, amount) {
            emit SellPassed(token);
        } catch Error(string memory reason) {
            emit SellBlocked(token, reason);
        }
    }
}
