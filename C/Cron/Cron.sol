// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CronSuite.sol
/// @notice On‑chain analogues of “cron” scheduling patterns:
///   Types: OneShot, Recurring, Delayed  
///   AttackTypes: UnauthorizedSchedule, FloodSchedule, RaceExecution  
///   DefenseTypes: AccessControl, RateLimit, ReentrancyGuard  

enum CronType           { OneShot, Recurring, Delayed }
enum CronAttackType     { UnauthorizedSchedule, FloodSchedule, RaceExecution }
enum CronDefenseType    { AccessControl, RateLimit, ReentrancyGuard }

error CRN__NotOwner();
error CRN__TooManySchedules();
error CRN__Reentrant();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SCHEDULER
//    • anyone may schedule any job at any time
//    • Attack: UnauthorizedSchedule
////////////////////////////////////////////////////////////////////////
contract CronVuln {
    event JobScheduled(address indexed who, CronType ctype, uint256 when, CronAttackType attack);

    function schedule(CronType ctype, uint256 when) external {
        // ❌ no access control
        emit JobScheduled(msg.sender, ctype, when, CronAttackType.UnauthorizedSchedule);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • floods scheduler with many jobs
//    • Attack: FloodSchedule
////////////////////////////////////////////////////////////////////////
contract Attack_Cron {
    CronVuln public target;
    constructor(CronVuln _t) { target = _t; }

    function flood(CronType ctype, uint256 when, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            target.schedule(ctype, when + i);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE SCHEDULER WITH ACCESS CONTROL
//    • Defense: AccessControl – only owner may schedule
////////////////////////////////////////////////////////////////////////
contract CronSafeAccess {
    address public owner;
    event JobScheduled(address indexed who, CronType ctype, uint256 when, CronDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function schedule(CronType ctype, uint256 when) external {
        if (msg.sender != owner) revert CRN__NotOwner();
        emit JobScheduled(msg.sender, ctype, when, CronDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE SCHEDULER WITH RATE‑LIMITING
//    • Defense: RateLimit – cap number of schedules per block per user
////////////////////////////////////////////////////////////////////////
contract CronSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    event JobScheduled(address indexed who, CronType ctype, uint256 when, CronDefenseType defense);
    error CRN__TooManySchedules();

    function schedule(CronType ctype, uint256 when) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert CRN__TooManySchedules();
        emit JobScheduled(msg.sender, ctype, when, CronDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////
// 5) SAFE SCHEDULER WITH REENTRANCY GUARD
//    • Defense: ReentrancyGuard – prevent race conditions on scheduling
////////////////////////////////////////////////////////////////////////
contract CronSafeGuard {
    bool private _entered;
    event JobScheduled(address indexed who, CronType ctype, uint256 when, CronDefenseType defense);

    modifier nonReentrant() {
        if (_entered) revert CRN__Reentrant();
        _entered = true;
        _;
        _entered = false;
    }

    function schedule(CronType ctype, uint256 when) external nonReentrant {
        // stub logic...
        emit JobScheduled(msg.sender, ctype, when, CronDefenseType.ReentrancyGuard);
    }
}
