// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WarChalkingSuite.sol
/// @notice On‑chain analogues of “War Chalking” patterns:
///   Types: LocationMark, LocationQuery, BulkMark, ExpiringMark  
///   AttackTypes: UnauthorizedMark, OverwriteMark, FloodMark, StaleMarkAccess  
///   DefenseTypes: OwnerAuth, ImmutableOnce, RateLimit, TTLExpire  

enum WarChalkingType         { LocationMark, LocationQuery, BulkMark, ExpiringMark }
enum WarChalkingAttackType   { UnauthorizedMark, OverwriteMark, FloodMark, StaleMarkAccess }
enum WarChalkingDefenseType  { OwnerAuth, ImmutableOnce, RateLimit, TTLExpire }

error WC__NotOwner();
error WC__AlreadyMarked();
error WC__TooManyMarks();
error WC__MarkExpired();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE MARK REGISTRY
///
///    • anyone may mark or overwrite any location  
///    • Attack: UnauthorizedMark, OverwriteMark  
///─────────────────────────────────────────────────────────────────────────────
contract WarChalkingVuln {
    mapping(string => address) public chalks; // location → marker

    event Chalked(string indexed location, address indexed by, WarChalkingAttackType attack);

    function mark(string calldata location) external {
        chalks[location] = msg.sender;
        emit Chalked(location, msg.sender, WarChalkingAttackType.OverwriteMark);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • UnauthorizedMark: attacker marks victim’s location  
///    • FloodMark: attacker floods many marks  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_WarChalking {
    WarChalkingVuln public target;

    constructor(WarChalkingVuln _t) { target = _t; }

    function spoofMark(string calldata location) external {
        target.mark(location);
    }

    function floodMarks(string[] calldata locations) external {
        for (uint i = 0; i < locations.length; i++) {
            target.mark(locations[i]);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE OWNER‑ONLY MARKING
///
///    • Defense: OwnerAuth – only contract owner may mark  
///─────────────────────────────────────────────────────────────────────────────
contract WarChalkingSafeOwner {
    mapping(string => address) public chalks;
    address public owner;

    event Chalked(string indexed location, address indexed by, WarChalkingDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function mark(string calldata location) external {
        if (msg.sender != owner) revert WC__NotOwner();
        chalks[location] = msg.sender;
        emit Chalked(location, msg.sender, WarChalkingDefenseType.OwnerAuth);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE IMMUTABLE & RATE‑LIMITED MARKING
///
///    • Defense: ImmutableOnce – first mark wins  
///               RateLimit – cap marks per block per user  
///─────────────────────────────────────────────────────────────────────────────
contract WarChalkingSafeAdvanced {
    mapping(string => address) public chalks;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_MARKS_PER_BLOCK = 5;

    error WC__TooManyMarks();

    event Chalked(string indexed location, address indexed by, WarChalkingDefenseType defense);

    function mark(string calldata location) external {
        // immutable once
        if (chalks[location] != address(0)) revert WC__AlreadyMarked();

        // rate‑limit per user per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_MARKS_PER_BLOCK) revert WC__TooManyMarks();

        chalks[location] = msg.sender;
        emit Chalked(location, msg.sender, WarChalkingDefenseType.RateLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE EXPIRING MARKS
///
///    • Defense: TTLExpire – marks expire after a TTL  
///─────────────────────────────────────────────────────────────────────────────
contract WarChalkingSafeTTL {
    struct Mark { address who; uint256 expiry; }
    mapping(string => Mark) public chalks;
    error WC__MarkExpired();

    event Chalked(string indexed location, address indexed by, WarChalkingDefenseType defense);

    function mark(string calldata location, uint256 ttl) external {
        chalks[location] = Mark({ who: msg.sender, expiry: block.timestamp + ttl });
        emit Chalked(location, msg.sender, WarChalkingDefenseType.TTLExpire);
    }

    function query(string calldata location) external view returns (address) {
        Mark memory m = chalks[location];
        if (block.timestamp > m.expiry) revert WC__MarkExpired();
        return m.who;
    }
}
