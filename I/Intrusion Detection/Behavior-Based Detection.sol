pragma solidity ^0.8.21;

contract BehaviorBasedIDS {
    mapping(address => bool) public normalUsers;
    address public admin;

    event BehaviorAnomaly(address user);

    constructor() {
        admin = msg.sender;
        normalUsers[admin] = true;
    }

    function markAsNormal(address user) external {
        require(msg.sender == admin, "Only admin");
        normalUsers[user] = true;
    }

    function callAdminFeature() external {
        if (!normalUsers[msg.sender]) {
            emit BehaviorAnomaly(msg.sender);
            revert("Unexpected behavior");
        }
        // Sensitive logic...
    }
}
