contract EmergencyReserves {
    address public dao;
    bool public disasterDeclared;
    mapping(address => uint256) public relief;

    constructor(address _dao) {
        dao = _dao;
    }

    function declareDisaster() external {
        require(msg.sender == dao, "Only DAO");
        disasterDeclared = true;
    }

    function claimRelief() external {
        require(disasterDeclared, "No declared disaster");
        require(relief[msg.sender] == 0, "Already claimed");
        relief[msg.sender] = 1 ether;
        payable(msg.sender).transfer(1 ether);
    }

    receive() external payable {}
}
