pragma solidity ^0.8.21;

contract TunnelSession {
    mapping(address => uint256) public sessionExpiry;
    uint256 public constant SESSION_DURATION = 1 hours;

    event SessionOpened(address user, uint256 expiresAt);

    function openTunnel() external {
        sessionExpiry[msg.sender] = block.timestamp + SESSION_DURATION;
        emit SessionOpened(msg.sender, sessionExpiry[msg.sender]);
    }

    modifier activeSession() {
        require(block.timestamp <= sessionExpiry[msg.sender], "Tunnel expired");
        _;
    }

    function useTunnel(bytes calldata data) external activeSession {
        // Execute tunneled logic
    }
}
