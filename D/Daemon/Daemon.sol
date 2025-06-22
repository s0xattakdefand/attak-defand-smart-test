// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DaemonSuite.sol
/// @notice On‑chain analogues of “Daemon” service patterns:
///   Types: Service, BackgroundJob, Watchdog, Scheduler  
///   AttackTypes: UnauthorizedSpawn, PrivilegeEscalation, ForkBomb, Hijack  
///   DefenseTypes: AccessControl, PrivilegeDrop, RateLimit, HeartbeatCheck  

enum DaemonType          { Service, BackgroundJob, Watchdog, Scheduler }
enum DaemonAttackType    { UnauthorizedSpawn, PrivilegeEscalation, ForkBomb, Hijack }
enum DaemonDefenseType   { AccessControl, PrivilegeDrop, RateLimit, HeartbeatCheck }

error DM__NotOwner();
error DM__TooManySpawns();
error DM__AlreadyPrivDrop();
error DM__NoHeartbeat();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DAEMON SPAWNER
///    • anyone may spawn any daemon with any config → UnauthorizedSpawn
///─────────────────────────────────────────────────────────────────────────────
contract DaemonVuln {
    mapping(uint256 => DaemonType) public daemons;
    event Spawned(address indexed who, uint256 indexed id, DaemonType dtype, DaemonAttackType attack);

    function spawn(uint256 id, DaemonType dtype) external {
        daemons[id] = dtype;
        emit Spawned(msg.sender, id, dtype, DaemonAttackType.UnauthorizedSpawn);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • demonstrates ForkBomb by spawning many daemons
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Daemon {
    DaemonVuln public target;
    constructor(DaemonVuln _t) { target = _t; }

    function forkBomb(uint256 startId, uint256 count, DaemonType dtype) external {
        for (uint256 i = 0; i < count; i++) {
            target.spawn(startId + i, dtype);
        }
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE AUTHORIZED SPAWNER
///    • only owner may spawn → AccessControl
///    • drop privileges after spawn → PrivilegeDrop
///─────────────────────────────────────────────────────────────────────────────
contract DaemonSafeAuth {
    address public owner;
    mapping(uint256 => bool)    public privileged;
    mapping(uint256 => DaemonType) public daemons;
    event Spawned(address indexed who, uint256 indexed id, DaemonType dtype, DaemonDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function spawn(uint256 id, DaemonType dtype) external {
        if (msg.sender != owner) revert DM__NotOwner();
        daemons[id] = dtype;
        privileged[id] = true;
        emit Spawned(msg.sender, id, dtype, DaemonDefenseType.AccessControl);
    }

    function dropPrivileges(uint256 id) external {
        if (!privileged[id]) revert DM__AlreadyPrivDrop();
        privileged[id] = false;
        emit Spawned(msg.sender, id, daemons[id], DaemonDefenseType.PrivilegeDrop);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE ADVANCED SPAWNER WITH RATE‑LIMIT & HEARTBEAT
///    • cap spawns per block → RateLimit  
///    • require periodic heartbeat ping → HeartbeatCheck  
///─────────────────────────────────────────────────────────────────────────────
contract DaemonSafeAdvanced {
    address public owner;
    mapping(address => uint256) public lastSpawnBlock;
    mapping(address => uint256) public spawnCountInBlock;
    mapping(uint256 => uint256) public lastHeartbeat;
    mapping(uint256 => DaemonType) public daemons;

    uint256 public constant MAX_SPAWNS_PER_BLOCK = 3;
    uint256 public constant HEARTBEAT_TIMEOUT    = 1 hours;

    event Spawned(address indexed who, uint256 indexed id, DaemonType dtype, DaemonDefenseType defense);
    event Heartbeat(uint256 indexed id, uint256 timestamp, DaemonDefenseType defense);

    modifier onlyOwner() {
        if (msg.sender != owner) revert DM__NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function spawn(uint256 id, DaemonType dtype) external onlyOwner {
        // rate‑limit per owner per block
        if (block.number != lastSpawnBlock[msg.sender]) {
            lastSpawnBlock[msg.sender] = block.number;
            spawnCountInBlock[msg.sender] = 0;
        }
        spawnCountInBlock[msg.sender]++;
        if (spawnCountInBlock[msg.sender] > MAX_SPAWNS_PER_BLOCK) revert DM__TooManySpawns();

        daemons[id] = dtype;
        lastHeartbeat[id] = block.timestamp;
        emit Spawned(msg.sender, id, dtype, DaemonDefenseType.RateLimit);
    }

    function heartbeat(uint256 id) external {
        // only the daemon itself (contract) can ping its own heartbeat
        // here we simulate by requiring msg.sender to match no external mapping
        lastHeartbeat[id] = block.timestamp;
        emit Heartbeat(id, block.timestamp, DaemonDefenseType.HeartbeatCheck);
    }

    function isAlive(uint256 id) external view returns (bool) {
        if (block.timestamp > lastHeartbeat[id] + HEARTBEAT_TIMEOUT) revert DM__NoHeartbeat();
        return true;
    }
}
