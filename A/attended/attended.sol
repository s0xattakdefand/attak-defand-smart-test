// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AttendedRegistry - Tracks on-chain attendance to events or actions

contract AttendedRegistry {
    address public eventOrganizer;
    string public eventLabel;
    uint256 public eventStart;
    uint256 public eventEnd;

    mapping(address => bool) public attended;

    event Attended(address indexed user, string label, uint256 timestamp);

    constructor(string memory _label, uint256 _durationMinutes) {
        eventOrganizer = msg.sender;
        eventLabel = _label;
        eventStart = block.timestamp;
        eventEnd = block.timestamp + (_durationMinutes * 1 minutes);
    }

    function markAttendance() external {
        require(block.timestamp >= eventStart && block.timestamp <= eventEnd, "Outside attendance window");
        require(!attended[msg.sender], "Already marked");

        attended[msg.sender] = true;
        emit Attended(msg.sender, eventLabel, block.timestamp);
    }

    function hasAttended(address user) external view returns (bool) {
        return attended[user];
    }
}
