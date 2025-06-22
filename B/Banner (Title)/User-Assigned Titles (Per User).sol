contract UserTitles {
    mapping(address => string) public userTitles;

    function setMyTitle(string calldata newTitle) public {
        userTitles[msg.sender] = newTitle;
    }

    function getMyTitle() public view returns (string memory) {
        return userTitles[msg.sender];
    }
}
