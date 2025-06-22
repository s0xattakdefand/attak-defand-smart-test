function safeTransfer(address to, uint256 amount) external {
    require(to != address(0), "Zero address");
    require(balances[msg.sender] >= amount, "Insufficient");

    balances[msg.sender] -= amount;
    balances[to] += amount;
}
