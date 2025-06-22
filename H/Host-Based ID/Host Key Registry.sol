contract HostKeyRegistry {
    mapping(address => bool) public approvedHosts;

    modifier onlyHost() {
        require(approvedHosts[msg.sender], "Not a verified host");
        _;
    }

    function registerHost(address host) external {
        // assume access control
        approvedHosts[host] = true;
    }

    function callHostAction() external onlyHost {
        // sensitive logic
    }
}
