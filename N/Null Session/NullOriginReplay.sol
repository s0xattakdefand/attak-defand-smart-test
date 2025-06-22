contract NullOriginReplay {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function dangerousWithdraw() external {
        require(tx.origin == admin, "Invalid origin"); // ❌ vulnerable to smart contract forwarding
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
