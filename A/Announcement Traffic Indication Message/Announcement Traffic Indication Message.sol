// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ATIMBroadcaster is AccessControl {
    bytes32 public constant BROADCASTER_ROLE = keccak256("BROADCASTER_ROLE");

    struct ATIMMessage {
        address sender;
        string payload;
        uint256 timestamp;
        uint256 expiry; // seconds
    }

    mapping(bytes32 => ATIMMessage) public atimMessages;
    mapping(address => uint256) public lastBroadcast;

    uint256 public cooldown = 30; // seconds

    event ATIMBroadcasted(bytes32 indexed id, address indexed sender, string payload, uint256 expiry);
    event ATIMExpired(bytes32 indexed id);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BROADCASTER_ROLE, msg.sender);
    }

    modifier rateLimited() {
        require(block.timestamp >= lastBroadcast[msg.sender] + cooldown, "ATIM cooldown active");
        _;
    }

    /// @notice Broadcast a new ATIM (announcement)
    function broadcastATIM(string calldata payload, uint256 ttl)
        external onlyRole(BROADCASTER_ROLE) rateLimited
    {
        require(bytes(payload).length > 0, "Payload required");
        require(ttl <= 3600, "TTL too long");

        bytes32 atimId = keccak256(abi.encodePacked(msg.sender, block.timestamp, payload));
        atimMessages[atimId] = ATIMMessage({
            sender: msg.sender,
            payload: payload,
            timestamp: block.timestamp,
            expiry: block.timestamp + ttl
        });

        lastBroadcast[msg.sender] = block.timestamp;

        emit ATIMBroadcasted(atimId, msg.sender, payload, block.timestamp + ttl);
    }

    /// @notice Check if ATIM is active
    function isATIMActive(bytes32 atimId) public view returns (bool) {
        ATIMMessage memory m = atimMessages[atimId];
        return m.timestamp != 0 && block.timestamp < m.expiry;
    }

    /// @notice Clean up an expired ATIM (optional gas refund)
    function expireATIM(bytes32 atimId) external {
        require(!isATIMActive(atimId), "ATIM still active");
        delete atimMessages[atimId];
        emit ATIMExpired(atimId);
    }

    /// @notice Admin updates cooldown rate
    function setCooldown(uint256 newCooldown) external onlyRole(DEFAULT_ADMIN_ROLE) {
        cooldown = newCooldown;
    }
}
