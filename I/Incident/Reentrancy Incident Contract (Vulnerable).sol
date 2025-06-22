contract ReentrancyIncident {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Nothing to withdraw");

        (bool sent, ) = msg.sender.call{value: bal}(""); // 🚨 vulnerable!
        require(sent, "Send failed");

        balances[msg.sender] = 0; // 💣 state change after call
    }
}
