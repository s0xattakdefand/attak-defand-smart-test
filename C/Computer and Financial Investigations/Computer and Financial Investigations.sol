// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ForensicAuditTrail {
    address public investigator;
    mapping(address => bool) public flagged;
    mapping(address => uint256) public balance;
    mapping(address => string) public notes;

    event FundsReceived(address indexed from, uint256 amount);
    event FundsTransferred(address indexed from, address indexed to, uint256 amount);
    event AddressFlagged(address indexed suspect, string reason);
    event InvestigationNoteAdded(address indexed subject, string note);

    modifier onlyInvestigator() {
        require(msg.sender == investigator, "Not authorized");
        _;
    }

    constructor() {
        investigator = msg.sender;
    }

    function deposit() external payable {
        balance[msg.sender] += msg.value;
        emit FundsReceived(msg.sender, msg.value);
    }

    function transfer(address to, uint256 amount) external {
        require(!flagged[msg.sender], "Sender under investigation");
        require(balance[msg.sender] >= amount, "Insufficient balance");
        balance[msg.sender] -= amount;
        balance[to] += amount;
        emit FundsTransferred(msg.sender, to, amount);
    }

    function flag(address suspect, string calldata reason) external onlyInvestigator {
        flagged[suspect] = true;
        emit AddressFlagged(suspect, reason);
    }

    function addNote(address subject, string calldata note) external onlyInvestigator {
        notes[subject] = note;
        emit InvestigationNoteAdded(subject, note);
    }

    function getNote(address subject) external view returns (string memory) {
        return notes[subject];
    }
}
