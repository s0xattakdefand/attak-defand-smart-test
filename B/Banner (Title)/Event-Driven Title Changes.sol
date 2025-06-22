contract LevelBasedBanner {
    mapping(address => uint256) public userLevel;
    mapping(address => string) public banners;

    function increaseLevel() public {
        userLevel[msg.sender]++;
        if (userLevel[msg.sender] == 10) {
            banners[msg.sender] = "Veteran";
        } else if (userLevel[msg.sender] == 1) {
            banners[msg.sender] = "Rookie";
        }
    }

    function getMyBanner() public view returns (string memory) {
        return banners[msg.sender];
    }
}
