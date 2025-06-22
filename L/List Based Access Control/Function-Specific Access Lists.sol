pragma solidity ^0.8.21;

contract RoleBasedLBAC {
    mapping(address => bool) public voters;
    mapping(address => bool) public stakers;

    function setVoter(address user, bool allowed) external {
        voters[user] = allowed;
    }

    function setStaker(address user, bool allowed) external {
        stakers[user] = allowed;
    }

    modifier onlyVoter() {
        require(voters[msg.sender], "Not a voter");
        _;
    }

    modifier onlyStaker() {
        require(stakers[msg.sender], "Not a staker");
        _;
    }

    function vote() external onlyVoter {
        // Voting logic
    }

    function stake() external onlyStaker {
        // Staking logic
    }
}
