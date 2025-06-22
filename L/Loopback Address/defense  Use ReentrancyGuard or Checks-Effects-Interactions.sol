function safeWithdraw() external {
    require(!locked, "No reentrancy");
    locked = true;

    uint256 payout = balance;
    balance = 0;

    (bool sent, ) = msg.sender.call{value: payout}("");
    require(sent, "Transfer failed");

    locked = false;
}
