pragma solidity ^0.8.21;

contract X500Directory {
    struct Entity {
        string country;
        string organization;
        string commonName;
    }

    mapping(address => Entity) public directory;

    function registerEntity(string memory c, string memory o, string memory cn) external {
        directory[msg.sender] = Entity(c, o, cn);
    }

    function getEntity(address user) external view returns (Entity memory) {
        return directory[user];
    }
}
