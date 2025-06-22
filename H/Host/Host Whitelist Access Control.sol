contract HostGuard {
    mapping(address => bool) public trustedHosts;

    modifier onlyHost() {
        require(trustedHosts[msg.sender], "Not a verified host");
        _;
    }

    function addHost(address host) external {
        // Assume admin-only in practice
        trustedHosts[host] = true;
    }

    function executeAsHost(string calldata action) external onlyHost {
        // Host-restricted logic
    }
}
