// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommunityCloudRegistry {
    address public admin;

    struct Member {
        string name;
        address controller;  // EOA or contract
        uint256 joinedAt;
        bool active;
    }

    mapping(address => Member) public members;
    address[] public memberList;

    event MemberJoined(address indexed controller, string name);
    event MemberRevoked(address indexed controller);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function join(string calldata name, address controller) external onlyAdmin {
        require(members[controller].joinedAt == 0, "Already a member");

        members[controller] = Member({
            name: name,
            controller: controller,
            joinedAt: block.timestamp,
            active: true
        });

        memberList.push(controller);
        emit MemberJoined(controller, name);
    }

    function revoke(address controller) external onlyAdmin {
        require(members[controller].active, "Not active");
        members[controller].active = false;
        emit MemberRevoked(controller);
    }

    function isActive(address controller) external view returns (bool) {
        return members[controller].active;
    }

    function getMembers() external view returns (address[] memory) {
        return memberList;
    }
}
