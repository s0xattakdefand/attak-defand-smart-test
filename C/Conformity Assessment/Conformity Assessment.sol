// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConformityAssessmentRegistry {
    address public admin;

    struct Assessment {
        string item;
        bool passed;
        string notes;
        uint256 timestamp;
    }

    mapping(address => Assessment[]) public assessments;

    event AssessmentLogged(address indexed target, string item, bool passed, string notes);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logAssessment(address target, string calldata item, bool passed, string calldata notes) external onlyAdmin {
        assessments[target].push(Assessment(item, passed, notes, block.timestamp));
        emit AssessmentLogged(target, item, passed, notes);
    }

    function getAssessments(address target) external view returns (Assessment[] memory) {
        return assessments[target];
    }
}
