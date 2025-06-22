// 👿 No log emitted on fund withdrawal
function withdraw(uint256 amount) external {
    require(msg.sender == owner, "Not owner");
    payable(msg.sender).transfer(amount);
    // <-- No emit Withdrawal event
}
