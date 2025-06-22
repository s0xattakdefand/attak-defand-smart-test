// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract COPEAccessControl {
    address public immutable corporateOwner;

    struct Delegation {
        uint256 dailyLimit;
        uint256 usedToday;
        uint256 lastResetDay;
        bool enabled;
    }

    mapping(address => Delegation) public delegates;

    event DelegateEnabled(address indexed user, uint256 limit);
    event DelegateDisabled(address indexed user);
    event ActionPerformed(address indexed user, uint256 amount, string purpose);

    modifier onlyCorporate() {
        require(msg.sender == corporateOwner, "COPE: Not corporate owner");
        _;
    }

    modifier onlyEnabled() {
        require(delegates[msg.sender].enabled, "COPE: Not enabled");
        _;
    }

    constructor() {
        corporateOwner = msg.sender;
    }

    function enableDelegate(address user, uint256 limit) external onlyCorporate {
        delegates[user] = Delegation(limit, 0, block.timestamp / 1 days, true);
        emit DelegateEnabled(user, limit);
    }

    function disableDelegate(address user) external onlyCorporate {
        delegates[user].enabled = false;
        emit DelegateDisabled(user);
    }

    function performAction(uint256 amount, string calldata purpose) external onlyEnabled {
        Delegation storage d = delegates[msg.sender];

        // Reset daily usage if a new day
        uint256 today = block.timestamp / 1 days;
        if (d.lastResetDay < today) {
            d.usedToday = 0;
            d.lastResetDay = today;
        }

        require(d.usedToday + amount <= d.dailyLimit, "COPE: Limit exceeded");

        d.usedToday += amount;

        emit ActionPerformed(msg.sender, amount, purpose);

        // Action logic would go here (e.g., token withdrawal, module execution)
    }

    // View delegate status
    function getDelegateStatus(address user) external view returns (
        uint256 dailyLimit,
        uint256 usedToday,
        uint256 lastResetDay,
        bool enabled
    ) {
        Delegation memory d = delegates[user];
        return (d.dailyLimit, d.usedToday, d.lastResetDay, d.enabled);
    }
}
