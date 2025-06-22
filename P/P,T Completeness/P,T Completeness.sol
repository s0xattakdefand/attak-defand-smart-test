// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PTCompletenessAttackDefense - Attack and Defense Simulation for P,T Completeness in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure State Machine (Deadlocks, Orphan Functions, No Transition Validation)
contract InsecurePT {
    enum State { Init, Pending, Approved, Rejected, Completed }

    State public currentState;

    event StateTransition(State oldState, State newState);

    constructor() {
        currentState = State.Init;
    }

    function approve() external {
        // 🔥 No state checks — can approve from anywhere!
        emit StateTransition(currentState, State.Approved);
        currentState = State.Approved;
    }

    function reject() external {
        // 🔥 No validation — can reject even after completion!
        emit StateTransition(currentState, State.Rejected);
        currentState = State.Rejected;
    }

    function complete() external {
        emit StateTransition(currentState, State.Completed);
        currentState = State.Completed;
    }
}

/// @notice Secure State Machine with Full P,T Completeness Enforcement
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePT is Ownable {
    enum State { Init, Pending, Approved, Rejected, Completed }

    State public currentState;

    event StateTransition(State indexed oldState, State indexed newState);

    constructor() {
        currentState = State.Init;
    }

    function moveToPending() external onlyOwner {
        require(currentState == State.Init, "Must be in Init");
        _transition(State.Pending);
    }

    function approve() external onlyOwner {
        require(currentState == State.Pending, "Must be Pending to Approve");
        _transition(State.Approved);
    }

    function reject() external onlyOwner {
        require(currentState == State.Pending, "Must be Pending to Reject");
        _transition(State.Rejected);
    }

    function complete() external onlyOwner {
        require(currentState == State.Approved, "Must be Approved to Complete");
        _transition(State.Completed);
    }

    function _transition(State newState) internal {
        State oldState = currentState;
        currentState = newState;
        emit StateTransition(oldState, newState);
    }
}

/// @notice Attack contract simulating illegal transition attempts
contract PTIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function forceApprove() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("approve()")
        );
    }

    function forceReject() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("reject()")
        );
    }
}
