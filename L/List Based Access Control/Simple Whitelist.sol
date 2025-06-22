pragma solidity ^0.8.21;

contract WhitelistAccess {
    mapping(address => bool) public whitelist;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyWhitelisted() {
        require(whitelist[msg.sender], "Not whitelisted");
        _;
    }

    function updateWhitelist(address user, bool allowed) external {
        require(msg.sender == admin, "Not admin");
        whitelist[user] = allowed;
    }

    function sensitiveAction() external onlyWhitelisted {
        // Only whitelisted users can perform this
    }
}
