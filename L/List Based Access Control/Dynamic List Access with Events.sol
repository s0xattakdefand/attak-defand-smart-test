pragma solidity ^0.8.21;

contract DynamicLBAC {
    mapping(address => bool) public mintList;
    address public admin;

    event ListUpdated(address user, bool allowed);

    constructor() {
        admin = msg.sender;
    }

    function updateMintList(address user, bool allowed) external {
        require(msg.sender == admin, "Only admin");
        mintList[user] = allowed;
        emit ListUpdated(user, allowed);
    }

    function mint() external {
        require(mintList[msg.sender], "Not allowed to mint");
        // Mint logic
    }
}
