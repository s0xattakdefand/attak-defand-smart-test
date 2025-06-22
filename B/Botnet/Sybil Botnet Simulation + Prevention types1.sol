contract SybilBotAttack {
    mapping(address => bool) public hasClaimed;
    uint256 public claimAmount = 1 ether;

    function claim() public {
        require(!hasClaimed[msg.sender], "Already claimed");
        hasClaimed[msg.sender] = true;
        payable(msg.sender).transfer(claimAmount);
    }

    receive() external payable {}
}
