pragma solidity ^0.8.21;

contract QualityGovernance {
    address public admin;
    string public latestImprovement;
    event ImprovementProposed(string description);

    constructor() {
        admin = msg.sender;
    }

    function proposeImprovement(string memory description) external {
        latestImprovement = description;
        emit ImprovementProposed(description);
    }

    function getLatestProposal() external view returns (string memory) {
        return latestImprovement;
    }
}
