contract ZeroDayReentrancyGap {
    mapping(address => uint256) public balance;
    bool private entered;

    event Claimed(address user, uint256 amount);

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function claim() external {
        require(!entered, "Reentrant call");
        entered = true;

        uint256 amount = balance[msg.sender];
        require(amount > 0, "Nothing");

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        balance[msg.sender] = 0;
        entered = false;
        emit Claimed(msg.sender, amount);
    }
}
