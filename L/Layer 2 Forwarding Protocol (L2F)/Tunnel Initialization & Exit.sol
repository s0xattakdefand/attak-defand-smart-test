pragma solidity ^0.8.21;

contract L2Tunnel {
    mapping(address => bool) public activeTunnels;
    event TunnelOpened(address user);
    event TunnelClosed(address user);

    function openTunnel() external {
        activeTunnels[msg.sender] = true;
        emit TunnelOpened(msg.sender);
    }

    function closeTunnel() external {
        require(activeTunnels[msg.sender], "No active tunnel");
        activeTunnels[msg.sender] = false;
        emit TunnelClosed(msg.sender);
    }

    function forwardThroughTunnel(address target, bytes calldata data) external {
        require(activeTunnels[msg.sender], "Tunnel not open");
        (bool success, ) = target.call(data);
        require(success, "Tunnel forwarding failed");
    }
}
