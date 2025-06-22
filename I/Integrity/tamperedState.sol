contract IntegrityBroken {
    mapping(address => uint256) public balances;

    function updateBalance(address user, uint256 newBalance) external {
        balances[user] = newBalance; // ❌ No access control or verification
    }
}
