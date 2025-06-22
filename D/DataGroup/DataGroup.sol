// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DataGroupAttackDefense - Full Attack and Defense Simulation for Data Groups
/// @author ChatGPT

contract SecureDataGroup {
    address public owner;
    mapping(address => bool) public members;
    uint256 public memberCount;
    uint256 public constant MAX_MEMBERS = 100;

    event MemberAdded(address indexed newMember);
    event MemberRemoved(address indexed removedMember);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addMember(address _member) external onlyOwner {
        require(!members[_member], "Already a member");
        require(memberCount < MAX_MEMBERS, "Member limit reached");

        members[_member] = true;
        memberCount++;

        emit MemberAdded(_member);
    }

    function removeMember(address _member) external onlyOwner {
        require(members[_member], "Not a member");

        members[_member] = false;
        memberCount--;

        emit MemberRemoved(_member);
    }

    function isMember(address _addr) external view returns (bool) {
        return members[_addr];
    }
}

/// @notice Attack contract trying to force inject itself into the SecureDataGroup
contract AttackDataGroup {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function forceInject() external {
        // Attempt to call addMember with msg.sender to inject attacker
        (bool success, ) = target.call(
            abi.encodeWithSignature("addMember(address)", msg.sender)
        );
        require(success, "Injection failed");
    }
}
