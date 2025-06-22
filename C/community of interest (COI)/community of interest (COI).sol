// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommunityOfInterestRegistry {
    address public admin;

    struct Member {
        string label;
        uint256 joinedAt;
        bool active;
    }

    string public communityName;
    mapping(address => Member) public members;
    address[] public memberList;

    event MemberJoined(address indexed member, string label);
    event MemberRemoved(address indexed member);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(string memory name) {
        admin = msg.sender;
        communityName = name;
    }

    function joinCommunity(address user, string calldata label) external onlyAdmin {
        require(!members[user].active, "Already a member");

        members[user] = Member({
            label: label,
            joinedAt: block.timestamp,
            active: true
        });

        memberList.push(user);
        emit MemberJoined(user, label);
    }

    function removeMember(address user) external onlyAdmin {
        require(members[user].active, "Not active");
        members[user].active = false;
        emit MemberRemoved(user);
    }

    function isMember(address user) public view returns (bool) {
        return members[user].active;
    }

    function listMembers() external view returns (address[] memory) {
        return memberList;
    }
}
