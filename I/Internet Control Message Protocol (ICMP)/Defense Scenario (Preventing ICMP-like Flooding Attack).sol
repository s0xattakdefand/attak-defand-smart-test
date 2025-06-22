pragma solidity ^0.8.21;

contract NodeHealthMonitor {
    address public admin;
    uint256 public constant HEARTBEAT_INTERVAL = 60; // in seconds

    struct NodeInfo {
        uint256 lastHeartbeat;
        bool active;
    }

    mapping(address => NodeInfo) public nodes;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier throttle(address node) {
        require(
            block.timestamp - nodes[node].lastHeartbeat >= HEARTBEAT_INTERVAL,
            "Heartbeat: Too frequent"
        );
        _;
    }

    function registerNode(address node) external onlyAdmin {
        nodes[node] = NodeInfo(block.timestamp, true);
    }

    function heartbeat(address node) external throttle(node) {
        require(nodes[node].active, "Heartbeat: Inactive node");
        nodes[node].lastHeartbeat = block.timestamp;
    }

    function deactivateNode(address node) external onlyAdmin {
        nodes[node].active = false;
    }
}
