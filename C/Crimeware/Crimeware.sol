// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CrimeWarSuite.sol
/// @notice On‑chain analogues of “CrimeWar” conflict reporting patterns:
///   Types: Organized, Cyber, Terrorist  
///   AttackTypes: Collusion, Extortion, Fraud, DataBreach  
///   DefenseTypes: Enforcement, Surveillance, RateLimit, ImmutableReport  

enum CrimeWarType         { Organized, Cyber, Terrorist }
enum CrimeWarAttackType   { Collusion, Extortion, Fraud, DataBreach }
enum CrimeWarDefenseType  { Enforcement, Surveillance, RateLimit, ImmutableReport }

error CW__NotOwner();
error CW__TooManyReports();
error CW__AlreadyReported();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE REPORTING REGISTRY
//
//    • anyone may report any conflict at any time  
//    • Attack: false or spam reports  
////////////////////////////////////////////////////////////////////////
contract CrimeWarVuln {
    mapping(uint256 => CrimeWarType) public reports;
    event Reported(
        uint256 indexed id,
        CrimeWarType       kind,
        CrimeWarAttackType attack
    );

    /// ❌ no access control or rate‑limit
    function report(uint256 id, CrimeWarType kind) external {
        reports[id] = kind;
        emit Reported(id, kind, CrimeWarAttackType.Fraud);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • attacker floods or fakes conflict reports  
////////////////////////////////////////////////////////////////////////
contract Attack_CrimeWar {
    CrimeWarVuln public target;
    constructor(CrimeWarVuln _t) { target = _t; }

    /// flood many false reports
    function flood(uint256[] calldata ids, CrimeWarType kind) external {
        for (uint i = 0; i < ids.length; i++) {
            target.report(ids[i], kind);
        }
    }

    /// submit a single malicious report
    function spoof(uint256 id) external {
        target.report(id, CrimeWarType.Terrorist);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE OWNER‑ONLY REPORTING
//
//    • Defense: Enforcement – only owner may report  
//               Surveillance – log reporter  
////////////////////////////////////////////////////////////////////////
contract CrimeWarSafe {
    mapping(uint256 => CrimeWarType) public reports;
    address public owner;
    event Reported(
        uint256 indexed id,
        CrimeWarType       kind,
        CrimeWarDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function report(uint256 id, CrimeWarType kind) external {
        if (msg.sender != owner) revert CW__NotOwner();
        reports[id] = kind;
        emit Reported(id, kind, CrimeWarDefenseType.Enforcement);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE RATE‑LIMITED REPORTING WITH IMMUTABLE ONCE
//
//    • Defense: RateLimit – cap reports per block per user  
//               ImmutableReport – once set, cannot be overwritten  
////////////////////////////////////////////////////////////////////////
contract CrimeWarSafeRateLimit {
    mapping(uint256 => CrimeWarType) public reports;
    mapping(address => uint256)   public lastBlock;
    mapping(address => uint256)   public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 3;
    event Reported(
        uint256 indexed id,
        CrimeWarType       kind,
        CrimeWarDefenseType defense
    );

    function report(uint256 id, CrimeWarType kind) external {
        // immutable once
        if (reports[id] != CrimeWarType.Organized &&
            reports[id] != CrimeWarType.Cyber &&
            reports[id] != CrimeWarType.Terrorist) {
            // no prior report → ok
        } else {
            revert CW__AlreadyReported();
        }

        // rate‑limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert CW__TooManyReports();

        reports[id] = kind;
        emit Reported(id, kind, CrimeWarDefenseType.RateLimit);
    }
}
