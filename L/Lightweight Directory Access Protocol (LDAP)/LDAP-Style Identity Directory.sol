pragma solidity ^0.8.21;

contract IdentityDirectory {
    struct LDAPEntry {
        string username;
        string org;
        string role;
    }

    mapping(address => LDAPEntry) public directory;

    function register(string memory user, string memory org, string memory role) external {
        directory[msg.sender] = LDAPEntry(user, org, role);
    }

    function getRole(address user) external view returns (string memory) {
        return directory[user].role;
    }
}
