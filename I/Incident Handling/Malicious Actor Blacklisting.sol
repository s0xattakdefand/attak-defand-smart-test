contract AccessRevoker {
    mapping(address => bool) public blacklisted;

    modifier notBlacklisted() {
        require(!blacklisted[msg.sender], "Blacklisted");
        _;
    }

    function blacklist(address maliciousActor) external {
        blacklisted[maliciousActor] = true;
    }

    function safeAction() external notBlacklisted {
        // safe contract logic
    }
}
