// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConsortiumManager {
    address public admin;
    mapping(address => bool) public members;
    uint256 public quorum;
    mapping(bytes32 => uint256) public approvals;

    event MemberAdded(address member);
    event MemberRemoved(address member);
    event ActionApproved(bytes32 action, address by);
    event QuorumChanged(uint256 newQuorum);

    modifier onlyMember() {
        require(members[msg.sender], "Not consortium member");
        _;
    }

    constructor(address[] memory initialMembers, uint256 _quorum) {
        admin = msg.sender;
        for (uint256 i = 0; i < initialMembers.length; i++) {
            members[initialMembers[i]] = true;
        }
        quorum = _quorum;
    }

    function addMember(address newMember) external onlyMember {
        require(!members[newMember], "Already member");
        members[newMember] = true;
        emit MemberAdded(newMember);
    }

    function removeMember(address oldMember) external onlyMember {
        require(members[oldMember], "Not a member");
        members[oldMember] = false;
        emit MemberRemoved(oldMember);
    }

    function setQuorum(uint256 newQuorum) external {
        require(msg.sender == admin, "Not admin");
        quorum = newQuorum;
        emit QuorumChanged(newQuorum);
    }

    function approveAction(bytes32 actionHash) external onlyMember {
        approvals[actionHash]++;
        emit ActionApproved(actionHash, msg.sender);
    }

    function isQuorumReached(bytes32 actionHash) external view returns (bool) {
        return approvals[actionHash] >= quorum;
    }
}
