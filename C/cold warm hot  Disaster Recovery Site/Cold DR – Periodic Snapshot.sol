contract ColdDRBackup {
    address public admin;
    mapping(address => uint256) public snapshotBalances;
    uint256 public lastSnapshotTime;

    constructor() {
        admin = msg.sender;
    }

    // Admin triggers a snapshot
    function snapshot(address[] calldata users, uint256[] calldata bals) external {
        require(msg.sender == admin, "Not admin");
        require(users.length == bals.length, "Mismatch arrays");
        lastSnapshotTime = block.timestamp;
        for (uint i=0; i < users.length; i++){
            snapshotBalances[users[i]] = bals[i];
        }
    }
}
