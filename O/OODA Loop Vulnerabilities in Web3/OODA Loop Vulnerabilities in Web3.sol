// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title OODAattackDefense - Attack and Defense Simulation for Observe-Orient-Decide-Act (OODA) Loops in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure OODA Contract (No Data Freshness Check, No Decision Validation)
contract InsecureOODA {
    uint256 public lastObservedPrice;
    uint256 public decision;
    bool public actionExecuted;

    event Observed(uint256 price);
    event DecisionMade(uint256 decision);
    event ActionExecuted(string outcome);

    function observe(uint256 price) external {
        lastObservedPrice = price;
        emit Observed(price);
    }

    function orientAndDecide() external {
        // 🔥 No freshness, no cross-check
        if (lastObservedPrice > 1000 ether) {
            decision = 1; // Buy
        } else {
            decision = 2; // Sell
        }
        emit DecisionMade(decision);
    }

    function act() external {
        require(decision != 0, "No decision made");

        if (decision == 1) {
            actionExecuted = true;
            emit ActionExecuted("Buy executed");
        } else if (decision == 2) {
            actionExecuted = true;
            emit ActionExecuted("Sell executed");
        }
    }
}

/// @notice Secure OODA Contract (Freshness Validation, Safe Orientation, Decision Commit-Reveal)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureOODA is Ownable {
    uint256 public lastObservedPrice;
    uint256 public observationTimestamp;
    uint256 public decisionHash;
    bool public decisionCommitted;
    bool public actionExecuted;

    uint256 public constant MAX_OBSERVATION_DELAY = 5 minutes;

    event Observed(uint256 price, uint256 timestamp);
    event DecisionCommitted(bytes32 decisionHash);
    event ActionExecuted(string outcome);

    function observe(uint256 price) external onlyOwner {
        lastObservedPrice = price;
        observationTimestamp = block.timestamp;
        emit Observed(price, block.timestamp);
    }

    function orientAndCommitDecision(uint256 _decision) external onlyOwner {
        require(block.timestamp - observationTimestamp <= MAX_OBSERVATION_DELAY, "Stale observation");
        require(!decisionCommitted, "Decision already committed");

        decisionHash = keccak256(abi.encodePacked(_decision, address(this)));
        decisionCommitted = true;
        emit DecisionCommitted(decisionHash);
    }

    function act(uint256 revealedDecision) external onlyOwner {
        require(decisionCommitted, "No decision committed");
        require(keccak256(abi.encodePacked(revealedDecision, address(this))) == decisionHash, "Invalid decision reveal");

        actionExecuted = true;

        if (revealedDecision == 1) {
            emit ActionExecuted("Buy executed");
        } else if (revealedDecision == 2) {
            emit ActionExecuted("Sell executed");
        } else {
            revert("Unknown action");
        }

        // Reset for next cycle
        decisionCommitted = false;
        decisionHash = 0;
    }
}

/// @notice Attack contract simulating stale observation drift
contract OODAIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function injectFakeObservation(uint256 fakePrice) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("observe(uint256)", fakePrice)
        );
    }
}
