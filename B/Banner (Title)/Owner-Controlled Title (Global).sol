contract GlobalTitle {
    string public title;
    address public owner;

    constructor(string memory _title) {
        title = _title;
        owner = msg.sender;
    }

    function updateTitle(string calldata newTitle) public {
        require(msg.sender == owner, "Not allowed");
        title = newTitle;
    }
}
