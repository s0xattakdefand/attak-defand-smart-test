contract RaceConditionGuarded {
    mapping(address => uint256) public balance;

    event Claimed(address indexed user, uint256 amount);

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function claim() external {
        uint256 amount = balance[msg.sender];
        require(amount > 0, "Nothing to claim");

        balance[msg.sender] = 0; // ✅ set to 0 BEFORE transferring

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        emit Claimed(msg.sender, amount);
    }
}
