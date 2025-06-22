pragma solidity ^0.8.21;

contract IdentityRegistryISO {
    mapping(address => string) public identities;
    event IdentityRegistered(address user, string id);

    function registerIdentity(string memory id) external {
        identities[msg.sender] = id;
        emit IdentityRegistered(msg.sender, id);
    }

    function getIdentity(address user) external view returns (string memory) {
        return identities[user];
    }
}
