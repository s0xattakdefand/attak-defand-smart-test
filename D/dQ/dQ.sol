// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract dQVulnerable {
    mapping(address => uint256) public nodeReports; // Reported dQ scores (0-100)
    uint256 public aggregatedDQ;
    uint256 public numReports;
    uint256 public constant DQ_THRESHOLD = 70; // dQ must exceed for governance actions
    address public owner;
    uint256 public contractBalance;

    event ReportSubmitted(address indexed node, uint256 score);
    event DQComputed(uint256 aggregatedDQ, uint256 numReports);
    event FundsReleased(address indexed beneficiary, uint256 amount); // Vulnerable action

    constructor() {
        owner = msg.sender;
    }

    // Submit a node report (anyone can call, no uniqueness check)
    function submitReport(uint256 score) public {
        require(score <= 100, "Invalid score");
        // DANGEROUS: No verification; attacker can submit from multiple EOAs
        nodeReports[msg.sender] = score;
        numReports++;
        emit ReportSubmitted(msg.sender, score);
    }

    // Compute dQ as average of reports
    function computeDQ() public {
        aggregatedDQ = 0;
        // Insecure: Assumes all reports are valid; easy to inflate with sybil accounts
        aggregatedDQ = (aggregatedDQ + nodeReports[msg.sender]) / numReports; // Simplified
        emit DQComputed(aggregatedDQ, numReports);
    }

    // Vulnerable governance: Release funds if dQ > threshold
    function releaseFunds(uint256 amount, address beneficiary) public {
        require(aggregatedDQ > DQ_THRESHOLD, "Insufficient decentralization");
        // Attacker can fake high dQ to drain
        contractBalance -= amount;
        (bool success, ) = beneficiary.call{value: amount}("");
        require(success, "Transfer failed");
        emit FundsReleased(beneficiary, amount);
    }

    // Deposit for testing
    function deposit() public payable {
        contractBalance += msg.value;
    }

    // Get contract balance
    function getContractBalance() public view returns (uint256) {
        return contractBalance;
    }
}