contract VaultNoBIA {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Not enough");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount); // 💥 vulnerable: no check during reentrancy
    }
}
