// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DefenseInDepthSuite.sol
/// @notice On‑chain analogues of “Defense in Depth” patterns:
///   Types: Perimeter, Network, Application, Data  
///   AttackTypes: FirewallBypass, PacketSniff, Injection, Exfiltration  
///   DefenseTypes: Firewall, IDS, InputValidation, Encryption  

enum DIDType            { Perimeter, Network, Application, Data }
enum DIDAttackType      { FirewallBypass, PacketSniff, Injection, Exfiltration }
enum DIDDefenseType     { Firewall, IDS, InputValidation, Encryption }

error DID__Bypass();
error DID__Detected();
error DID__InvalidInput();
error DID__NoKey();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE NO‑LAYER
///
///    • no defenses: anyone can bypass and exfiltrate  
///    • Attack: Exfiltration  
///─────────────────────────────────────────────────────────────────────────────
contract DefenseInDepthVuln {
    mapping(uint256 => bytes) public dataStore;
    event Accessed(address indexed who, uint256 indexed id, DIDAttackType attack);

    function store(uint256 id, bytes calldata data) external {
        dataStore[id] = data;
    }
    function access(uint256 id) external {
        emit Accessed(msg.sender, id, DIDAttackType.Exfiltration);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • bypass and sniff  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DefenseInDepth {
    DefenseInDepthVuln public target;
    constructor(DefenseInDepthVuln _t) { target = _t; }

    function hack(uint256 id) external {
        // attacker directly accesses data
        target.access(id);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE PERIMETER + NETWORK DEFENSE
///
///    • Defense: Firewall – only allowed addrs  
///               IDS – detect multiple attempts  
///─────────────────────────────────────────────────────────────────────────────
contract DefenseInDepthSafeLayer1 {
    mapping(address => bool)    public allowed;
    mapping(address => uint256) public lastBlock;
    mapping(uint256 => bytes)   public dataStore;
    event Accessed(address indexed who, uint256 indexed id, DIDDefenseType defense);

    constructor() { allowed[msg.sender] = true; }
    function setAllowed(address who, bool ok) external { allowed[who] = ok; }

    function store(uint256 id, bytes calldata data) external {
        dataStore[id] = data;
    }

    function access(uint256 id) external {
        if (!allowed[msg.sender]) revert DID__Bypass();
        // simple IDS: detect repeated access in same block
        if (block.number == lastBlock[msg.sender]) revert DID__Detected();
        lastBlock[msg.sender] = block.number;
        emit Accessed(msg.sender, id, DIDDefenseType.Firewall);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) FULL DEFENSE IN DEPTH
///
///    • Defense: Application – input validation  
///               Data – encryption tag check  
///─────────────────────────────────────────────────────────────────────────────
contract DefenseInDepthSafeFull {
    mapping(address => bool)    public allowed;
    mapping(address => uint256) public lastBlock;
    mapping(uint256 => bytes)   public dataStore;
    bytes32 public key;
    event Accessed(address indexed who, uint256 indexed id, DIDDefenseType defense);

    constructor(bytes32 _key) {
        key = _key;
        allowed[msg.sender] = true;
    }
    function setAllowed(address who, bool ok) external {
        allowed[who] = ok;
    }

    function store(uint256 id, bytes calldata data) external {
        // Application layer: validate length
        if (data.length == 0 || data.length > 1024) revert DID__InvalidInput();
        dataStore[id] = data;
    }

    function access(uint256 id, bytes32 tag) external {
        if (!allowed[msg.sender]) revert DID__Bypass();
        if (block.number == lastBlock[msg.sender]) revert DID__Detected();
        lastBlock[msg.sender] = block.number;
        // Data layer: check encryption tag
        bytes32 expected = keccak256(abi.encodePacked(dataStore[id], key));
        if (expected != tag) revert DID__InvalidInput();
        emit Accessed(msg.sender, id, DIDDefenseType.Encryption);
    }
}
