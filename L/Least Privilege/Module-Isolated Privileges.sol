pragma solidity ^0.8.21;

contract ModuleController {
    mapping(address => bool) public canControlStaking;
    mapping(address => bool) public canControlTreasury;

    function setStakingPrivilege(address user, bool allowed) external {
        canControlStaking[user] = allowed;
    }

    function setTreasuryPrivilege(address user, bool allowed) external {
        canControlTreasury[user] = allowed;
    }

    function stake(uint256 amount) external {
        require(canControlStaking[msg.sender], "No stake rights");
        // stake logic
    }

    function withdrawTreasury() external {
        require(canControlTreasury[msg.sender], "No treasury rights");
        // withdrawal logic
    }
}
