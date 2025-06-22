// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AdversaryTracker — Logs and scores adversarial interactions
contract AdversaryTracker {
    address public admin;

    mapping(address => uint256) public suspicionScore;
    mapping(address => bool) public flaggedAdversary;

    event InteractionLogged(address indexed actor, string actionType, uint256 score);
    event ActorFlagged(address indexed actor, uint256 totalScore);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// Called by external contract to report potential adversarial action
    function reportAction(address actor, string calldata actionType, uint256 weight) external onlyAdmin {
        suspicionScore[actor] += weight;
        emit InteractionLogged(actor, actionType, suspicionScore[actor]);

        if (suspicionScore[actor] >= 100 && !flaggedAdversary[actor]) {
            flaggedAdversary[actor] = true;
            emit ActorFlagged(actor, suspicionScore[actor]);
        }
    }

    function isAdversary(address actor) external view returns (bool) {
        return flaggedAdversary[actor];
    }

    function resetActor(address actor) external onlyAdmin {
        suspicionScore[actor] = 0;
        flaggedAdversary[actor] = false;
    }
}
