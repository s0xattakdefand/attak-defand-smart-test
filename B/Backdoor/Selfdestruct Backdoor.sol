contract SelfDestructBackdoor {
    address public creator;

    constructor() {
        creator = msg.sender;
    }

    function destroy() public {
        require(msg.sender == creator, "Unauthorized");
        selfdestruct(payable(creator));
    }

    receive() external payable {}
}
