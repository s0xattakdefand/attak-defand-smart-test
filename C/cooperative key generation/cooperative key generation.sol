// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CooperativeKeyGeneration {
    address public admin;
    uint256 public participantCount;
    uint256 public threshold;

    struct Participant {
        bool registered;
        bytes share;
        bool hasSubmitted;
    }

    mapping(address => Participant) public participants;
    address[] public participantList;

    bytes public combinedKey;
    bool public keyGenerated;

    event ParticipantRegistered(address participant);
    event ShareSubmitted(address participant, bytes share);
    event KeyGenerated(bytes combinedKey);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    modifier onlyParticipant() {
        require(participants[msg.sender].registered, "Not registered participant");
        _;
    }

    constructor(uint256 _threshold) {
        require(_threshold > 1, "Threshold too low");
        admin = msg.sender;
        threshold = _threshold;
    }

    // Register participants by admin
    function registerParticipant(address _participant) external onlyAdmin {
        require(!participants[_participant].registered, "Already registered");
        participants[_participant].registered = true;
        participantList.push(_participant);
        participantCount++;

        emit ParticipantRegistered(_participant);
    }

    // Participants submit their verifiable shares
    function submitShare(bytes memory _share) external onlyParticipant {
        require(!participants[msg.sender].hasSubmitted, "Share already submitted");
        participants[msg.sender].share = _share;
        participants[msg.sender].hasSubmitted = true;

        emit ShareSubmitted(msg.sender, _share);
    }

    // Verify shares off-chain; combine on-chain
    function generateCombinedKey(bytes memory _combinedKey) external onlyAdmin {
        require(!keyGenerated, "Key already generated");

        uint256 submittedShares = 0;
        for (uint256 i = 0; i < participantList.length; i++) {
            if (participants[participantList[i]].hasSubmitted) {
                submittedShares++;
            }
        }

        require(submittedShares >= threshold, "Not enough shares submitted");

        combinedKey = _combinedKey;
        keyGenerated = true;

        emit KeyGenerated(_combinedKey);
    }

    // Get participant's submitted share
    function getShare(address _participant) external view returns (bytes memory) {
        require(participants[_participant].hasSubmitted, "Share not submitted");
        return participants[_participant].share;
    }
}
