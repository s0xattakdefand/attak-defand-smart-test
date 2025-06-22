// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonTierRegistry {
    address public deployer;

    enum Tier { NONE, TIER1, TIER2, TIER3 }

    mapping(address => Tier) public userTier;

    event TierAssigned(address indexed user, Tier tier);
    event TierRevoked(address indexed user);

    modifier onlyTier1() {
        require(userTier[msg.sender] == Tier.TIER1, "Not Tier 1");
        _;
    }

    constructor() {
        deployer = msg.sender;
        userTier[msg.sender] = Tier.TIER1;
        emit TierAssigned(msg.sender, Tier.TIER1);
    }

    function assignTier(address user, Tier tier) external onlyTier1 {
        require(tier != Tier.NONE, "Invalid tier");
        userTier[user] = tier;
        emit TierAssigned(user, tier);
    }

    function revokeTier(address user) external onlyTier1 {
        userTier[user] = Tier.NONE;
        emit TierRevoked(user);
    }

    function isTier(address user, Tier tier) external view returns (bool) {
        return userTier[user] == tier;
    }

    function getTier(address user) external view returns (Tier) {
        return userTier[user];
    }
}
