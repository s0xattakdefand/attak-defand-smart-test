// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title PerimeterSuite.sol
/// @notice On-chain analogues of “Perimeter” security boundary patterns:
///   Types: Physical, Network, Application, Virtual  
///   AttackTypes: Bypass, DDoS, Spoofing, Evasion  
///   DefenseTypes: Firewall, RateLimit, IDS, DeepInspection

enum PerimeterType         { Physical, Network, Application, Virtual }
enum PerimeterAttackType   { Bypass, DDoS, Spoofing, Evasion }
enum PerimeterDefenseType  { Firewall, RateLimit, IDS, DeepInspection }

error PR__NotAllowed();
error PR__TooManyRequests();
error PR__Blocked();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PERIMETER
//
//    • ❌ no controls: any caller may traverse → Bypass
////////////////////////////////////////////////////////////////////////////////
contract PerimeterVuln {
    event Breach(
        address indexed who,
        uint256           zone,
        PerimeterType     ptype,
        PerimeterAttackType attack
    );

    function traverse(uint256 zone, PerimeterType ptype) external {
        emit Breach(msg.sender, zone, ptype, PerimeterAttackType.Bypass);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates DDoS flooding & spoofing
////////////////////////////////////////////////////////////////////////////////
contract Attack_Perimeter {
    PerimeterVuln public target;
    constructor(PerimeterVuln _t) { target = _t; }

    /// flood with many traverse calls (DDoS)
    function flood(uint256 zone, PerimeterType ptype, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.traverse(zone, ptype);
        }
    }

    /// spoof traversal type
    function spoof(uint256 zone) external {
        target.traverse(zone, PerimeterType.Network);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH FIREWALL (ACCESS CONTROL)
//    • ✅ Defense: Firewall – only whitelisted addresses may traverse
////////////////////////////////////////////////////////////////////////////////
contract PerimeterSafeFirewall {
    mapping(address => bool) public allowed;
    address public owner;
    event Traverse(
        address indexed who,
        uint256           zone,
        PerimeterType     ptype,
        PerimeterDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function setAllowed(address user, bool ok) external {
        require(msg.sender == owner, "only owner");
        allowed[user] = ok;
    }

    function traverse(uint256 zone, PerimeterType ptype) external {
        if (!allowed[msg.sender]) revert PR__NotAllowed();
        emit Traverse(msg.sender, zone, ptype, PerimeterDefenseType.Firewall);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RATE-LIMITING
//
//    • ✅ Defense: RateLimit – cap traversals per block per address
////////////////////////////////////////////////////////////////////////////////
contract PerimeterSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event Traverse(
        address indexed who,
        uint256           zone,
        PerimeterType     ptype,
        PerimeterDefenseType defense
    );

    error PR__TooManyRequests();

    function traverse(uint256 zone, PerimeterType ptype) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert PR__TooManyRequests();
        emit Traverse(msg.sender, zone, ptype, PerimeterDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH IDS & DEEP INSPECTION
//
//    • ✅ Defense: IDS – detect anomalous patterns  
//               DeepInspection – inspect payload signature
////////////////////////////////////////////////////////////////////////////////
contract PerimeterSafeAdvanced {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public attemptsInBlock;
    mapping(address => uint256) public blockedUntil;
    uint256 public constant MAX_ATTEMPTS = 3;

    event Traverse(
        address indexed who,
        uint256           zone,
        PerimeterType     ptype,
        bytes             payload,
        PerimeterDefenseType defense
    );
    event Alert(
        address indexed who,
        string            reason,
        PerimeterDefenseType defense
    );

    error PR__Blocked();

    constructor() {}

    function traverse(uint256 zone, PerimeterType ptype, bytes calldata payload) external {
        // check block on block list
        if (block.number < blockedUntil[msg.sender]) revert PR__Blocked();

        // deep inspection: require payload starts with magic 0x50,0x43 ("PC")
        if (payload.length < 2 || payload[0] != 0x50 || payload[1] != 0x43) {
            emit Alert(msg.sender, "deep inspection failed", PerimeterDefenseType.DeepInspection);
            revert PR__Blocked();
        }

        // IDS: rate-limit attempts per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]      = block.number;
            attemptsInBlock[msg.sender] = 0;
        }
        attemptsInBlock[msg.sender]++;
        if (attemptsInBlock[msg.sender] > MAX_ATTEMPTS) {
            blockedUntil[msg.sender] = block.number + 10;
            emit Alert(msg.sender, "IDS threshold exceeded", PerimeterDefenseType.IDS);
            revert PR__Blocked();
        }

        emit Traverse(msg.sender, zone, ptype, payload, PerimeterDefenseType.DeepInspection);
    }
}
