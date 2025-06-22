// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommunicatingGroupRegistry {
    address public admin;

    // Group ID => (member => true)
    mapping(bytes32 => mapping(address => bool)) public groupMembers;
    mapping(bytes32 => address[]) public groupList;

    event MemberAdded(bytes32 indexed groupId, address indexed member);
    event MemberRemoved(bytes32 indexed groupId, address indexed member);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addMember(bytes32 groupId, address member) external onlyAdmin {
        require(!groupMembers[groupId][member], "Already in group");
        groupMembers[groupId][member] = true;
        groupList[groupId].push(member);
        emit MemberAdded(groupId, member);
    }

    function removeMember(bytes32 groupId, address member) external onlyAdmin {
        require(groupMembers[groupId][member], "Not in group");
        groupMembers[groupId][member] = false;
        emit MemberRemoved(groupId, member);
        // Optional: skip array cleanup for gas savings
    }

    function isGroupMember(bytes32 groupId, address member) external view returns (bool) {
        return groupMembers[groupId][member];
    }

    function getGroupMembers(bytes32 groupId) external view returns (address[] memory) {
        return groupList[groupId];
    }
}
