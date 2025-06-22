// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WarDialerSuite.sol
/// @notice On‑chain analogues of “War Dialer” patterns:
///   Types: SingleDial, BulkDial, SpoofDial, TimedDial  
///   AttackTypes: UnauthorizedDial, FloodDial, CallerIDSpoof, ExpiredDial  
///   DefenseTypes: AccessControl, RateLimit, CallerValidation, TTLExpire  

enum WarDialerType         { SingleDial, BulkDial, SpoofDial, TimedDial }
enum WarDialerAttackType   { UnauthorizedDial, FloodDial, CallerIDSpoof, ExpiredDial }
enum WarDialerDefenseType  { AccessControl, RateLimit, CallerValidation, TTLExpire }

error WD__NotOwner();
error WD__TooMany();
error WD__BadCallerID();
error WD__DialExpired();

////////////////////////////////////////////////////////////////////////
// 1) SINGLE DIAL (no access control)
//    • Vulnerable: anyone may dial any number
//    • Attack: unauthorized dial
//    • Defense: AccessControl
////////////////////////////////////////////////////////////////////////
contract WarDialerVuln1 {
    event Dial(address indexed caller, uint256 number, WarDialerAttackType attack);

    function dial(uint256 number) external {
        emit Dial(msg.sender, number, WarDialerAttackType.UnauthorizedDial);
    }
}

contract Attack_WarDialer1 {
    WarDialerVuln1 public target;
    constructor(WarDialerVuln1 _t) { target = _t; }

    function exploit(uint256 number) external {
        target.dial(number);
    }
}

contract WarDialerSafe1 {
    address public owner;
    event Dial(address indexed caller, uint256 number, WarDialerDefenseType defense);

    constructor() { owner = msg.sender; }

    function dial(uint256 number) external {
        if (msg.sender != owner) revert WD__NotOwner();
        emit Dial(msg.sender, number, WarDialerDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) BULK DIAL (flood)
//    • Vulnerable: unlimited bulk dialing → DoS
//    • Attack: flood dial
//    • Defense: RateLimit
////////////////////////////////////////////////////////////////////////
contract WarDialerVuln2 {
    event BulkDial(address indexed caller, uint256 number, WarDialerAttackType attack);

    function bulkDial(uint256[] calldata numbers) external {
        for (uint i = 0; i < numbers.length; i++) {
            emit BulkDial(msg.sender, numbers[i], WarDialerAttackType.FloodDial);
        }
    }
}

contract Attack_WarDialer2 {
    WarDialerVuln2 public target;
    constructor(WarDialerVuln2 _t) { target = _t; }

    function flood(uint256[] calldata numbers) external {
        target.bulkDial(numbers);
    }
}

contract WarDialerSafe2 {
    uint256 public constant MAX_BULK = 20;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    event BulkDial(address indexed caller, uint256 number, WarDialerDefenseType defense);

    function bulkDial(uint256[] calldata numbers) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender] += numbers.length;
        if (countInBlock[msg.sender] > MAX_BULK) revert WD__TooMany();
        for (uint i = 0; i < numbers.length; i++) {
            emit BulkDial(msg.sender, numbers[i], WarDialerDefenseType.RateLimit);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SPOOF DIAL (caller ID spoofing)
//    • Vulnerable: trusts supplied caller address
//    • Attack: spoof dialFrom
//    • Defense: CallerValidation
////////////////////////////////////////////////////////////////////////
contract WarDialerVuln3 {
    event DialFrom(address caller, address indexed from, uint256 number, WarDialerAttackType attack);

    function dialFrom(address from, uint256 number) external {
        emit DialFrom(msg.sender, from, number, WarDialerAttackType.CallerIDSpoof);
    }
}

contract Attack_WarDialer3 {
    WarDialerVuln3 public target;
    constructor(WarDialerVuln3 _t) { target = _t; }

    function spoof(address victim, uint256 number) external {
        target.dialFrom(victim, number);
    }
}

contract WarDialerSafe3 {
    event Dial(address indexed caller, uint256 number, WarDialerDefenseType defense);
    error WD__BadCallerID();

    function dialFrom(address /*from*/, uint256 number) external {
        // ignore supplied caller, use msg.sender
        if (msg.sender == address(0)) revert WD__BadCallerID();
        emit Dial(msg.sender, number, WarDialerDefenseType.CallerValidation);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) TIMED DIAL (permission with TTL)
//    • Vulnerable: sets permission but never checks expiry
//    • Attack: dial after TTL to bypass intent
//    • Defense: TTLExpire
////////////////////////////////////////////////////////////////////////
contract WarDialerVuln4 {
    mapping(uint256 => uint256) public permissionExpiry;

    function setPermission(uint256 number, uint256 ttl) external {
        permissionExpiry[number] = block.timestamp + ttl;
    }

    function dial(uint256 number) external view returns (bool) {
        // ❌ does not enforce expiry
        return true;
    }
}

contract Attack_WarDialer4 {
    WarDialerVuln4 public target;
    constructor(WarDialerVuln4 _t) { target = _t; }

    function exploit(uint256 number, uint256 ttl) external view returns (bool) {
        // after ttl expires off‑chain, dial still returns true
        return target.dial(number);
    }
}

contract WarDialerSafe4 {
    mapping(uint256 => uint256) public permissionExpiry;
    event Dial(address indexed caller, uint256 number, WarDialerDefenseType defense);

    function setPermission(uint256 number, uint256 ttl) external {
        permissionExpiry[number] = block.timestamp + ttl;
    }

    function dial(uint256 number) external {
        if (block.timestamp > permissionExpiry[number]) revert WD__DialExpired();
        emit Dial(msg.sender, number, WarDialerDefenseType.TTLExpire);
    }
}
