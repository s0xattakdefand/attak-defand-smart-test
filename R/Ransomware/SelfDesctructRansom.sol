contract SelfDestructRansom {
    address payable public owner;
    uint256 public deadline;
    bool public paid;

    constructor(uint256 duration) {
        owner = payable(msg.sender);
        deadline = block.timestamp + duration;
    }

    function payRansom() external payable {
        require(msg.value >= 1 ether, "Too low");
        paid = true;
    }

    function detonate() external {
        require(block.timestamp > deadline && !paid, "Not triggered");
        selfdestruct(owner);
    }
}
