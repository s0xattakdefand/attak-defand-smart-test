// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Exploit Without Trace, Fake Action Logs, Audit Evasion Attack
/// Defense Types: Immutable After Action Logs, Admin/Protocol Reporting Rights, Cross-Checkable Hashing

contract AfterActionReportSystem {
    address public admin;

    struct AAR {
        address actor;
        string actionType;
        string summary;
        uint256 timestamp;
        bytes32 reportHash;
    }

    AAR[] public reports;

    event ReportSubmitted(address indexed actor, string actionType, string summary, bytes32 reportHash, uint256 timestamp);
    event AttackDetected(address indexed actor, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can submit reports");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// ATTACK Simulation: Submit fake AAR without permission
    function attackSubmitFakeReport(string calldata actionType, string calldata summary) external {
        emit AttackDetected(msg.sender, "Unauthorized AAR submission attempt");
        revert("Not authorized to submit AAR");
    }

    /// DEFENSE: Submit a real After Action Report
    function submitAfterActionReport(string calldata actionType, string calldata summary) external onlyAdmin {
        bytes32 reportHash = keccak256(abi.encodePacked(msg.sender, actionType, summary, block.timestamp));

        reports.push(AAR({
            actor: msg.sender,
            actionType: actionType,
            summary: summary,
            timestamp: block.timestamp,
            reportHash: reportHash
        }));

        emit ReportSubmitted(msg.sender, actionType, summary, reportHash, block.timestamp);
    }

    /// View report by index
    function viewReport(uint256 index) external view returns (AAR memory) {
        require(index < reports.length, "Invalid report index");
        return reports[index];
    }

    /// Get total number of reports
    function getReportCount() external view returns (uint256) {
        return reports.length;
    }
}
