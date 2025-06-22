mapping(address => bool) public verified;

function verifyUser(address user, bytes calldata proof) external {
    // Connect with zk-proof or centralized oracle
    verified[user] = true;
}

modifier onlyVerified() {
    require(verified[msg.sender], "Not verified");
    _;
}
