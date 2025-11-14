// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "Effectiveness"
 *
 * 1. EffectivenessInsecure (vulnerable)
 * 2. EffectivenessSecure   (protected)
 * 3. EffectivenessAttacker (attack on insecure)
 *
 * Model:
 *   Each user has an "effectiveness score" (0–100)
 *   Ex: productivity, performance, trust score, KPI index, etc.
 */

/*//////////////////////////////////////////////////////////////
//                   INSECURE VERSION
//////////////////////////////////////////////////////////////*/

contract EffectivenessInsecure {
    struct Effect {
        uint256 score;    // 0–100 expected, but not enforced
        address owner;
    }

    mapping(address => Effect) public effectiveness;

    event ScoreSet(address indexed user, uint256 score);
    event ScoreForced(address indexed user, uint256 score);

    /**
     * ⚠️ VULN #1: Anyone can set their own effectiveness.
     */
    function setMyScore(uint256 score) external {
        effectiveness[msg.sender] = Effect({
            score: score,
            owner: msg.sender
        });

        emit ScoreSet(msg.sender, score);
    }

    /**
     * ⚠️ VULN #2: Anyone can force another user's score.
     */
    function forceScore(address user, uint256 score) external {
        effectiveness[user].score = score;
        effectiveness[user].owner = user;

        emit ScoreForced(user, score);
    }

    /**
     * ⚠️ VULN #3: No bounds checking.
     */
    function getScore(address user) external view returns (uint256) {
        return effectiveness[user].score;
    }

    function isHighPerforming(address user) external view returns (bool) {
        return effectiveness[user].score >= 80; // but exploitable
    }
}

/*//////////////////////////////////////////////////////////////
//                       OWNABLE UTILITY
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), owner);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }
}

/*//////////////////////////////////////////////////////////////
//                   SECURE / DEFENDED VERSION
//////////////////////////////////////////////////////////////*/

contract EffectivenessSecure is Ownable {
    struct Effect {
        uint256 score;    // 0–100 range enforced
        bool verified;    // Admin validation
        address owner;    // The user being rated
    }

    mapping(address => Effect) public effectiveness;

    event ScoreAssigned(address indexed user, uint256 score);
    event ScoreUpdated(address indexed user, uint256 score);
    event ScoreVerified(address indexed user, bool status);

    /**
     * Admin sets initial score. Cannot exceed 100.
     */
    function assignScore(address user, uint256 score) external onlyOwner {
        require(user != address(0), "INVALID_USER");
        require(score <= 100, "SCORE_TOO_HIGH");

        effectiveness[user] = Effect({
            score: score,
            verified: false,
            owner: user
        });

        emit ScoreAssigned(user, score);
    }

    /**
     * User may request score adjustment, but only owner updates.
     */
    function updateScore(address user, uint256 newScore) external onlyOwner {
        require(newScore <= 100, "OUT_OF_RANGE");
        require(effectiveness[user].owner != address(0), "NOT_EXIST");

        effectiveness[user].score = newScore;

        emit ScoreUpdated(user, newScore);
    }

    /**
     * Admin verification.
     */
    function verifyScore(address user, bool status) external onlyOwner {
        require(effectiveness[user].owner != address(0), "NOT_EXIST");
        effectiveness[user].verified = status;

        emit ScoreVerified(user, status);
    }

    /**
     * Proper validated check.
     */
    function getScore(address user) external view returns (uint256) {
        return effectiveness[user].score;
    }

    function isHighPerforming(address user) external view returns (bool) {
        Effect memory eff = effectiveness[user];
        return eff.verified && eff.score >= 80;
    }
}

/*//////////////////////////////////////////////////////////////
//                         ATTACKER
//////////////////////////////////////////////////////////////*/

contract EffectivenessAttacker {
    EffectivenessInsecure public target;

    constructor(address _target) {
        target = EffectivenessInsecure(_target);
    }

    /**
     * Step #1: Give self a huge "effectiveness"
     */
    function attackSetHugeScore() public {
        target.setMyScore(type(uint256).max); // overflow exploitation
    }

    /**
     * Step #2: Force high score on others (spoof)
     */
    function attackForceScore(address victim) public {
        target.forceScore(victim, type(uint256).max);
    }

    /**
     * Step #3: One-click exploit
     */
    function fullAttack(address victim) external {
        attackSetHugeScore();
        attackForceScore(victim);
    }
}
