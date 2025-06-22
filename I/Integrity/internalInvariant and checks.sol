mapping(address => uint256) private balances;

function transfer(address to, uint256 amount) external {
    uint256 previousSum = balances[msg.sender] + balances[to];

    require(balances[msg.sender] >= amount, "Insufficient");
    balances[msg.sender] -= amount;
    balances[to] += amount;

    require(balances[msg.sender] + balances[to] == previousSum, "State mismatch");
}
