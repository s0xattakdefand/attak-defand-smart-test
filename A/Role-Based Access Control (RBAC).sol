contract AuthWithRoles {
    mapping(address => bool) private admins;
    address public superAdmin;

    constructor() {
        superAdmin = msg.sender;
        admins[msg.sender] = true;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not an admin");
        _;
    }

    function setAdmin(address user, bool status) public {
        require(msg.sender == superAdmin, "Only super admin");
        admins[user] = status;
    }

    function adminFunction() public onlyAdmin {
        // Secure logic for admins only
    }
}
