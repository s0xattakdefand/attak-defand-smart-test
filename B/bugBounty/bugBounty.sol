// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title BugBountyAttackDefense - Bug Bounty Contract Attack and Defense Simulation for Solidity Smart Contracts
/// @author ChatGPT

/// @notice Insecure Bug Bounty Contract (No proof verification, No payout limits)
contract InsecureBugBounty {
    mapping(address => bool) public rewarded;

    event BugReported(address indexed reporter, uint256 amount);

    function reportBug(string calldata description) external payable {
        // 🔥 Accept any description without proof
        require(!rewarded[msg.sender], "Already rewarded");
        rewarded[msg.sender] = true;

        // Pay entire bounty pool to first reporter
        uint256 bounty = address(this).balance;
        payable(msg.sender).transfer(bounty);

        emit BugReported(msg.sender, bounty);
    }

    receive() external payable {}
}

/// @notice Secure Bug Bounty Contract with Commit-Reveal, Admin Verification, and Bounty Caps
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureBugBounty is Ownable {
    struct BugReport {
        address reporter;
        uint256 commitTimestamp;
        bytes32 bugCommitment;
        bool revealed;
        bool approved;
    }

    uint256 public constant MAX_BOUNTY = 5 ether;
    uint256 public constant COMMIT_REVEAL_DELAY = 1 hours;

    mapping(bytes32 => BugReport) public reports;
    mapping(address => bool) public hasClaimed;

    event BugCommitted(address indexed reporter, bytes32 commitment, uint256 timestamp);
    event BugRevealed(address indexed reporter, bytes32 commitment);
    event BountyAwarded(address indexed reporter, uint256 amount);

    function commitBug(bytes32 bugCommitment) external {
        require(!hasClaimed[msg.sender], "Already committed or claimed");

        reports[bugCommitment] = BugReport({
            reporter: msg.sender,
            commitTimestamp: block.timestamp,
            bugCommitment: bugCommitment,
            revealed: false,
            approved: false
        });

        emit BugCommitted(msg.sender, bugCommitment, block.timestamp);
    }

    function revealBug(string calldata bugDescription, bytes32 bugCommitment) external {
        BugReport storage report = reports[bugCommitment];

        require(msg.sender == report.reporter, "Not reporter");
        require(!report.revealed, "Already revealed");
        require(keccak256(abi.encodePacked(bugDescription)) == bugCommitment, "Invalid bug description");

        report.revealed = true;

        emit BugRevealed(msg.sender, bugCommitment);
    }

    function approveBug(bytes32 bugCommitment) external onlyOwner {
        BugReport storage report = reports[bugCommitment];
        require(report.revealed, "Bug not revealed");
        report.approved = true;
    }

    function claimBounty(bytes32 bugCommitment) external {
        BugReport storage report = reports[bugCommitment];

        require(msg.sender == report.reporter, "Not reporter");
        require(report.approved, "Bug not approved");
        require(!hasClaimed[msg.sender], "Already claimed");

        hasClaimed[msg.sender] = true;

        uint256 bounty = MAX_BOUNTY;
        if (address(this).balance < bounty) {
            bounty = address(this).balance;
        }

        payable(msg.sender).transfer(bounty);
        emit BountyAwarded(msg.sender, bounty);
    }

    receive() external payable {}
}

/// @notice Intruder trying to fake bug reports
contract BugBountyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function fakeBugReport(string calldata fakeDescription) external payable returns (bool success) {
        (success, ) = targetInsecure.call{value: msg.value}(
            abi.encodeWithSignature("reportBug(string)", fakeDescription)
        );
    }
}
