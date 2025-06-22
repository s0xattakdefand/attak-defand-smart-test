contract HashedRoleAccess {
    bytes32 public ADMIN_HASH;

    constructor(string memory secret) {
        ADMIN_HASH = keccak256(abi.encode(secret));
    }

    function check(bytes32 input) public view returns (bool) {
        return keccak256(abi.encode(input)) == ADMIN_HASH;
    }
}
