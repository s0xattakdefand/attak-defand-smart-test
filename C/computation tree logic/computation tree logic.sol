// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CTLStateMachine
/// @notice Demonstrates Computation Tree Logic via enforced transitions
contract CTLStateMachine {
    enum State { Uninitialized, Initialized, Active, Terminated }
    State public currentState;
    address public admin;

    event StateChanged(State from, State to);

    constructor() {
        admin = msg.sender;
        currentState = State.Uninitialized;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier validTransition(State next) {
        if (currentState == State.Uninitialized) require(next == State.Initialized, "Invalid transition");
        if (currentState == State.Initialized) require(next == State.Active, "Invalid transition");
        if (currentState == State.Active) require(next == State.Terminated, "Invalid transition");
        if (currentState == State.Terminated) revert("Terminated state is final");
        _;
    }

    function transition(State next) external onlyAdmin validTransition(next) {
        emit StateChanged(currentState, next);
        currentState = next;
    }

    /// @dev CTL property: AF Terminated (on all paths, must eventually terminate)
    function isFinal() external view returns (bool) {
        return currentState == State.Terminated;
    }
}
