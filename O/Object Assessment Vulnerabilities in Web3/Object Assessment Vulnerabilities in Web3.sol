// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObjectAssessmentAttackDefense - Attack and Defense Simulation for Object Assessment in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Object Assessment (Self-Settable and Manipulable Scores)
contract InsecureObjectAssessment {
    struct Profile {
        address owner;
        uint256 score;
        bool exists;
    }

    mapping(address => Profile) public profiles;

    event ProfileCreated(address indexed owner);
    event ScoreUpdated(address indexed owner, uint256 score);

    function createProfile() external {
        profiles[msg.sender] = Profile(msg.sender, 0, true);
        emit ProfileCreated(msg.sender);
    }

    function updateScore(uint256 newScore) external {
        require(profiles[msg.sender].exists, "Profile not found");
        profiles[msg.sender].score = newScore; // 🔥 User controls their own score!
        emit ScoreUpdated(msg.sender, newScore);
    }

    function isEligible(address user) external view returns (bool) {
        return profiles[user].score >= 100;
    }
}

/// @notice Secure Object Assessment (Onchain Immutable Score Evaluation)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureObjectAssessment is Ownable {
    struct Profile {
        address owner;
        uint256 activityPoints;
        bool exists;
    }

    mapping(address => Profile) private profiles;
    uint256 public constant MIN_ELIGIBLE_POINTS = 1000;

    event ProfileCreated(address indexed owner);
    event ActivityPointsUpdated(address indexed owner, uint256 totalPoints);

    function createProfile() external {
        require(!profiles[msg.sender].exists, "Profile already exists");
        profiles[msg.sender] = Profile(msg.sender, 0, true);
        emit ProfileCreated(msg.sender);
    }

    function recordActivity(address user, uint256 points) external onlyOwner {
        require(profiles[user].exists, "Profile not found");
        profiles[user].activityPoints += points;
        emit ActivityPointsUpdated(user, profiles[user].activityPoints);
    }

    function assessEligibility(address user) external view returns (bool) {
        Profile memory profile = profiles[user];
        return (profile.activityPoints >= MIN_ELIGIBLE_POINTS);
    }
}

/// @notice Attack contract simulating fake score inflation
contract AssessmentIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function inflateScore(uint256 fakeScore) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("updateScore(uint256)", fakeScore)
        );
    }
}
