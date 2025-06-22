// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Premature Authorization Attack, Assessment Forgery Attack, Skipped Evaluation Attack
/// Defense Types: Formal Assessment Enforcement, Secure Proof of Assessment, Authorization Binding to Assessment

contract AssessmentAndAuthorization {
    address public admin;

    struct Assessment {
        bool assessed;
        bool authorized;
        uint256 timestamp;
    }

    mapping(address => Assessment) public userAssessments;

    event AssessmentCompleted(address indexed user);
    event AuthorizationGranted(address indexed user);
    event AttackDetected(string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    /// ATTACK Simulation: Grant authorization without assessment
    function attackPrematureAuthorization(address user) external onlyAdmin {
        userAssessments[user].authorized = true; // unsafe direct authorization!
    }

    /// DEFENSE: Perform a formal assessment
    function performAssessment(address user) external onlyAdmin {
        userAssessments[user] = Assessment({
            assessed: true,
            authorized: false,
            timestamp: block.timestamp
        });

        emit AssessmentCompleted(user);
    }

    /// DEFENSE: After successful assessment, grant authorization
    function grantAuthorization(address user) external onlyAdmin {
        Assessment storage assessment = userAssessments[user];

        if (!assessment.assessed) {
            emit AttackDetected("Authorization attempted before assessment");
            revert("Cannot authorize without assessment");
        }

        assessment.authorized = true;
        emit AuthorizationGranted(user);
    }

    /// User-only function: require authorization to access
    function authorizedAction() external view returns (string memory) {
        require(userAssessments[msg.sender].authorized, "Not authorized yet");
        return "You are authorized to perform this action.";
    }

    /// View assessment status
    function viewAssessmentStatus(address user) external view returns (bool assessed, bool authorized, uint256 timestamp) {
        Assessment memory a = userAssessments[user];
        return (a.assessed, a.authorized, a.timestamp);
    }
}
