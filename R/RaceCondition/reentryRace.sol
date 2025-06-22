contract ReentrantVault {
    mapping(address => uint256) public balance;
    bool internal locked;

    event Claimed(address user, uint256 amount);

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function claim() external {
        require(!locked, "Locked");
        locked = true;

        uint256 amt = balance[msg.sender];
        require(amt > 0, "Nothing");

        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Fail");

        balance[msg.sender] = 0;
        emit Claimed(msg.sender, amt);

        locked = false;
    }
}
