pragma solidity ^0.8.21;

contract BlacklistAccess {
    mapping(address => bool) public blacklist;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    modifier notBlacklisted() {
        require(!blacklist[msg.sender], "Blacklisted");
        _;
    }

    function ban(address user) external {
        require(msg.sender == admin, "Not admin");
        blacklist[user] = true;
    }

    function access() external notBlacklisted {
        // Normal user access
    }
}
