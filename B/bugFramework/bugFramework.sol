// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BugFrameworkAttackDefense - Bug Framework Contract Attack and Defense Simulation for Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Bug Framework (No severity binding, No bug ID protection)
contract InsecureBugFramework {
    mapping(bytes32 => uint256) public rewards;

    event BugSubmitted(address indexed reporter, bytes32 bugId, string description);
    event RewardClaimed(address indexed reporter, uint256 amount);

    function submitBug(string calldata description) external {
        // 🔥 No commitment or proof; no severity management
        bytes32 bugId = keccak256(abi.encodePacked(description, block.timestamp, msg.sender));
        rewards[bugId] = address(this).balance;
        emit BugSubmitted(msg.sender, bugId, description);
    }

    function claimReward(bytes32 bugId) external {
        uint256 reward = rewards[bugId];
        require(reward > 0, "No reward");

        delete rewards[bugId];
        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, reward);
    }

    receive() external payable {}
}

/// @notice Secure Bug Framework with Severity Workflow, Bug ID Commit-Reveal, Reward Caps
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureBugFramework is Ownable {
    enum Severity { None, Low, Medium, High, Critical }

    struct BugReport {
        address reporter;
        uint256 timestamp;
        Severity severity;
        bool approved;
        bool rewardClaimed;
    }

    uint256 public constant LOW_REWARD = 0.5 ether;
    uint256 public constant MEDIUM_REWARD = 1 ether;
    uint256 public constant HIGH_REWARD = 2 ether;
    uint256 public constant CRITICAL_REWARD = 5 ether;

    mapping(bytes32 => BugReport) public reports;

    event BugCommitted(address indexed reporter, bytes32 bugId, uint256 timestamp);
    event BugApproved(address indexed admin, bytes32 bugId, Severity severity);
    event RewardClaimed(address indexed reporter, bytes32 bugId, uint256 amount);

    function commitBug(bytes32 bugId) external {
        require(reports[bugId].timestamp == 0, "Already submitted");

        reports[bugId] = BugReport({
            reporter: msg.sender,
            timestamp: block.timestamp,
            severity: Severity.None,
            approved: false,
            rewardClaimed: false
        });

        emit BugCommitted(msg.sender, bugId, block.timestamp);
    }

    function approveBug(bytes32 bugId, Severity severity) external onlyOwner {
        require(severity != Severity.None, "Invalid severity");
        BugReport storage report = reports[bugId];
        require(!report.approved, "Already approved");

        report.severity = severity;
        report.approved = true;

        emit BugApproved(msg.sender, bugId, severity);
    }

    function claimReward(bytes32 bugId) external {
        BugReport storage report = reports[bugId];

        require(report.reporter == msg.sender, "Not reporter");
        require(report.approved, "Bug not approved");
        require(!report.rewardClaimed, "Already claimed");

        uint256 reward;
        if (report.severity == Severity.Low) reward = LOW_REWARD;
        else if (report.severity == Severity.Medium) reward = MEDIUM_REWARD;
        else if (report.severity == Severity.High) reward = HIGH_REWARD;
        else if (report.severity == Severity.Critical) reward = CRITICAL_REWARD;
        else revert("Invalid severity");

        report.rewardClaimed = true;

        if (address(this).balance < reward) {
            reward = address(this).balance;
        }

        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, bugId, reward);
    }

    receive() external payable {}
}

/// @notice Intruder trying to inflate or race-claim rewards
contract BugFrameworkIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeSubmitBug(string calldata fakeDescription) external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("submitBug(string)", fakeDescription)
        );
    }
}
