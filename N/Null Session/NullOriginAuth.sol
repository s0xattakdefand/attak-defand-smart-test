contract NullOriginAuth {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function withdraw() external {
        require(tx.origin == admin, "Not authorized"); // ❌ Vulnerable to contract forwarding
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
