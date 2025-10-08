// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract DPSGDVulnerable {
    mapping(address => uint256) public userGradients;
    uint256 public aggregatedGradient;
    uint256 public numSubmissions;
    uint256 public constant NOISE_SCALE = 1; // Low noise: Vulnerable to reconstruction
    address public owner;

    event GradientSubmitted(address indexed user, uint256 gradient);
    event AggregationCompleted(uint256 aggregated, uint256 numSubs);
    event PrivacyLeak(address indexed attacker, address indexed target); // Simulates leak

    constructor() {
        owner = msg.sender;
    }

    // Submit private gradient (e.g., from local ML training)
    function submitGradient(uint256 gradient) public {
        // Simulate adding noise: Too low, easy to remove via averaging
        uint256 noisyGradient = gradient + (uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % NOISE_SCALE);
        userGradients[msg.sender] = noisyGradient;
        emit GradientSubmitted(msg.sender, noisyGradient);
    }

    // Vulnerable aggregation: Anyone can trigger, exposes raw submissions
    function aggregateGradients() public {
        require(numSubmissions < 10, "Max submissions reached"); // Limit for demo
        aggregatedGradient = 0;
        // Insecure: Loops over known users (assume off-chain tracking)
        // In practice, this would sum all submissions; here, simplified
        aggregatedGradient += userGradients[msg.sender]; // Demo: Add caller's
        numSubmissions++;
        // DANGEROUS: No privacy check; attacker can call multiple times to isolate
        if (numSubmissions > 1) {
            emit PrivacyLeak(msg.sender, address(0)); // Simulates leak via repeated calls
        }
        emit AggregationCompleted(aggregatedGradient, numSubmissions);
    }

    // Owner can update model (simplified SGD step)
    function updateModel() public {
        require(msg.sender == owner, "Not owner");
        // Simulate SGD: aggregatedGradient used to update weights (off-chain in real)
        aggregatedGradient /= numSubmissions; // Mean gradient
    }

    // Get contract balance (for potential staking in federated setup)
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}