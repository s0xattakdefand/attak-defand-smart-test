// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CoordinationCenter {
    address public coordinator;
    uint256 public coordinationNonce;
    uint256 public approvalThreshold;

    struct CoordinationEvent {
        bytes data;
        uint256 approvals;
        bool executed;
        mapping(address => bool) approvedBy;
    }

    mapping(uint256 => CoordinationEvent) private events;
    mapping(address => bool) public authorizedParticipants;
    uint256 public participantCount;

    event ParticipantAuthorized(address participant);
    event CoordinationProposed(uint256 nonce, bytes data);
    event CoordinationApproved(uint256 nonce, address approver, uint256 approvals);
    event CoordinationExecuted(uint256 nonce, bytes data);

    modifier onlyCoordinator() {
        require(msg.sender == coordinator, "Unauthorized coordinator");
        _;
    }

    modifier onlyAuthorizedParticipant() {
        require(authorizedParticipants[msg.sender], "Unauthorized participant");
        _;
    }

    constructor(uint256 _approvalThreshold) {
        require(_approvalThreshold > 0, "Invalid approval threshold");
        coordinator = msg.sender;
        approvalThreshold = _approvalThreshold;
        coordinationNonce = 1;
    }

    // Coordinator authorizes participants
    function authorizeParticipant(address _participant) external onlyCoordinator {
        require(!authorizedParticipants[_participant], "Already authorized");
        authorizedParticipants[_participant] = true;
        participantCount++;
        emit ParticipantAuthorized(_participant);
    }

    // Coordinator proposes coordination event
    function proposeCoordination(bytes memory _data) external onlyCoordinator {
        CoordinationEvent storage newEvent = events[coordinationNonce];
        newEvent.data = _data;
        newEvent.approvals = 0;
        newEvent.executed = false;

        emit CoordinationProposed(coordinationNonce, _data);
        coordinationNonce++;
    }

    // Participants approve coordination event
    function approveCoordination(uint256 nonce) external onlyAuthorizedParticipant {
        CoordinationEvent storage coordEvent = events[nonce];
        require(coordEvent.data.length > 0, "Coordination event not found");
        require(!coordEvent.executed, "Coordination already executed");
        require(!coordEvent.approvedBy[msg.sender], "Already approved");

        coordEvent.approvedBy[msg.sender] = true;
        coordEvent.approvals++;

        emit CoordinationApproved(nonce, msg.sender, coordEvent.approvals);

        if (coordEvent.approvals >= approvalThreshold) {
            executeCoordination(nonce);
        }
    }

    // Internal function executing coordination after threshold
    function executeCoordination(uint256 nonce) internal {
        CoordinationEvent storage coordEvent = events[nonce];
        require(!coordEvent.executed, "Already executed");
        require(coordEvent.approvals >= approvalThreshold, "Insufficient approvals");

        coordEvent.executed = true;

        // Implement actual coordination logic using coordEvent.data here

        emit CoordinationExecuted(nonce, coordEvent.data);
    }

    // Retrieve details of a coordination event
    function getCoordinationEvent(uint256 nonce) external view returns (
        bytes memory data,
        uint256 approvals,
        bool executed
    ) {
        CoordinationEvent storage coordEvent = events[nonce];
        return (coordEvent.data, coordEvent.approvals, coordEvent.executed);
    }
}
