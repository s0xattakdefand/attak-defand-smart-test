pragma solidity ^0.8.21;

contract LDAPGroupManager {
    mapping(string => mapping(address => bool)) public groupMembers;

    function joinGroup(string memory group) external {
        groupMembers[group][msg.sender] = true;
    }

    function leaveGroup(string memory group) external {
        groupMembers[group][msg.sender] = false;
    }

    function isInGroup(string memory group, address user) external view returns (bool) {
        return groupMembers[group][user];
    }
}
