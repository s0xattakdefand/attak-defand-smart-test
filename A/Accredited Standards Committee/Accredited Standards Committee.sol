// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AccreditedStandardsCommittee - On-chain committee for Web3 protocol standard governance

contract AccreditedStandardsCommittee {
    address public chair;
    mapping(address => bool) public committeeMembers;
    uint256 public approvalQuorum = 2;

    struct Standard {
        string name;
        string version;
        string specLink;      // IPFS or web link to full spec
        bytes32 contentHash;  // keccak256 of standard text or schema
        uint256 approvals;
        bool approved;
        mapping(address => bool) voted;
    }

    uint256 public standardCount;
    mapping(uint256 => Standard) private standards;

    event MemberAdded(address member);
    event StandardProposed(uint256 indexed id, string name, string version);
    event StandardApproved(uint256 indexed id, address approver);
    event StandardAccredited(uint256 indexed id, string name, string version);

    modifier onlyChair() {
        require(msg.sender == chair, "Not chair");
        _;
    }

    modifier onlyCommittee() {
        require(committeeMembers[msg.sender], "Not ASC member");
        _;
    }

    constructor(address[] memory initialMembers) {
        chair = msg.sender;
        for (uint i = 0; i < initialMembers.length; i++) {
            committeeMembers[initialMembers[i]] = true;
            emit MemberAdded(initialMembers[i]);
        }
    }

    function proposeStandard(
        string calldata name,
        string calldata version,
        string calldata specLink,
        bytes32 contentHash
    ) external onlyCommittee returns (uint256 id) {
        id = ++standardCount;
        Standard storage s = standards[id];
        s.name = name;
        s.version = version;
        s.specLink = specLink;
        s.contentHash = contentHash;
        emit StandardProposed(id, name, version);
    }

    function approveStandard(uint256 id) external onlyCommittee {
        Standard storage s = standards[id];
        require(!s.voted[msg.sender], "Already voted");
        require(!s.approved, "Already approved");

        s.voted[msg.sender] = true;
        s.approvals++;

        emit StandardApproved(id, msg.sender);

        if (s.approvals >= approvalQuorum) {
            s.approved = true;
            emit StandardAccredited(id, s.name, s.version);
        }
    }

    function getStandard(uint256 id) external view returns (
        string memory name,
        string memory version,
        string memory specLink,
        bytes32 contentHash,
        bool approved,
        uint256 approvals
    ) {
        Standard storage s = standards[id];
        return (s.name, s.version, s.specLink, s.contentHash, s.approved, s.approvals);
    }

    function addMember(address member) external onlyChair {
        committeeMembers[member] = true;
        emit MemberAdded(member);
    }
}
