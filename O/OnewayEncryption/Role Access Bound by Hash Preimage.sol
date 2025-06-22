contract BitGuardWithPreimage {
    mapping(address => uint8) public accessRoles;
    mapping(bytes32 => uint8) public preimageRoleMap;

    event RoleBound(bytes32 hash, uint8 role);
    event AccessGranted(address user, uint8 role);

    function bindPreimage(bytes32 hash, uint8 role) external {
        preimageRoleMap[hash] = role;
        emit RoleBound(hash, role);
    }

    function provePreimage(string calldata secret) external {
        bytes32 hash = keccak256(abi.encodePacked(secret));
        uint8 role = preimageRoleMap[hash];
        require(role > 0, "No role for hash");
        accessRoles[msg.sender] = role;
        emit AccessGranted(msg.sender, role);
    }

    modifier onlyRole(uint8 required) {
        require(accessRoles[msg.sender] == required, "Unauthorized");
        _;
    }

    function adminAction() external onlyRole(0xF0) {
        // Admins only (e.g., 0xF0 = admin)
    }
}
