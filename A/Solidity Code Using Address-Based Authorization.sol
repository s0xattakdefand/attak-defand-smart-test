contract OnlyAdminAuthorized {
    address public admin;
    uint256 public value;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized");
        _;
    }

    function setValue(uint256 newValue) public onlyAdmin {
        value = newValue;
    }

    function changeAdmin(address newAdmin) public onlyAdmin {
        admin = newAdmin;
    }
}
