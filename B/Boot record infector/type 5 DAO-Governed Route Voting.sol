contract DAORouteApproval {
    mapping(address => bool) public isApproved;
    address public dao;

    constructor(address _dao) {
        dao = _dao;
    }

    modifier onlyDAO() {
        require(msg.sender == dao, "Only DAO can approve");
        _;
    }

    function approveRoute(address gateway) public onlyDAO {
        isApproved[gateway] = true;
    }
}
