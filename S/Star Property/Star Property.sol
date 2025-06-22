// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StartPropertySuite.sol
/// @notice Four “Start‑Property” patterns around contract initialization,
///         each with a vulnerable module, a demo attack, and a hardened defense.

error SP__NotInitialized();
error SP__AlreadyInitialized();
error SP__TooManyInits();
error SP__InitExpired();

uint256 constant INIT_WINDOW = 1 days;
uint256 constant MAX_INITS    = 3;

////////////////////////////////////////////////////////////////////////
// 1) NO INITIALIZATION CHECK
//
//   • Vulnerable: functions may be called before initialize()
//   • Attack: call doWork() before initialize → unprotected logic
//   • Defense: require initialized flag in modifiers
////////////////////////////////////////////////////////////////////////
contract InitVuln1 {
    address public owner;
    uint256 public counter;

    /// initialize owner
    function initialize(address _owner) external {
        owner = _owner;
    }

    /// vulnerable: no check for initialization
    function doWork() external {
        // attacker can call before owner set
        counter += 1;
    }
}

contract Attack_InitVuln1 {
    InitVuln1 public target;
    constructor(InitVuln1 _t) { target = _t; }
    function exploit() external {
        // call doWork before initialize()
        target.doWork();
    }
}

contract InitSafe1 {
    address public owner;
    uint256 public counter;
    bool    public initialized;

    modifier onlyInitialized() {
        if (!initialized) revert SP__NotInitialized();
        _;
    }

    /// one‑time initialization
    function initialize(address _owner) external {
        require(!initialized, "already inited");
        owner = _owner;
        initialized = true;
    }

    /// safe: guard with initialization check
    function doWork() external onlyInitialized {
        counter += 1;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) REINITIALIZATION VULNERABILITY
//
//   • Vulnerable: initialize() can be called multiple times → hijack owner
//   • Attack: call initialize() twice to change owner to attacker
//   • Defense: mark initialized and prevent re‑init
////////////////////////////////////////////////////////////////////////
contract InitVuln2 {
    address public owner;

    function initialize(address _owner) external {
        owner = _owner; // no guard
    }
}

contract Attack_InitVuln2 {
    InitVuln2 public target;
    constructor(InitVuln2 _t) { target = _t; }
    function hijack() external {
        // first caller sets legitimate owner,
        // then attacker calls again to steal ownership
        target.initialize(msg.sender);
    }
}

contract InitSafe2 {
    address public owner;
    bool    private _inited;
    error SP__AlreadyInitialized();

    function initialize(address _owner) external {
        if (_inited) revert SP__AlreadyInitialized();
        owner = _owner;
        _inited = true;
    }
}

////////////////////////////////////////////////////////////////////////
// 3) BULK INITIALIZATIONS (DOS)
//
//   • Vulnerable: no cap on how many times modules are initialized
//   • Attack: call batchInitialize() many times to exhaust gas/storage
//   • Defense: enforce MAX_INITS per deployer
////////////////////////////////////////////////////////////////////////
contract InitVuln3 {
    address[] public modules;

    function batchInitialize(address[] calldata mods) external {
        for (uint i; i < mods.length; i++) {
            modules.push(mods[i]);
        }
    }
}

contract Attack_InitVuln3 {
    InitVuln3 public target;
    constructor(InitVuln3 _t) { target = _t; }
    function flood(address[] calldata mods) external {
        target.batchInitialize(mods);
    }
}

contract InitSafe3 {
    address[] public modules;
    mapping(address => uint256) public initCount;
    error SP__TooManyInits();

    function batchInitialize(address[] calldata mods) external {
        uint256 c = initCount[msg.sender] + 1;
        if (c > MAX_INITS) revert SP__TooManyInits();
        initCount[msg.sender] = c;

        for (uint i; i < mods.length; i++) {
            modules.push(mods[i]);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 4) EXPIRED INITIALIZATION WINDOW
//
//   • Vulnerable: initialize() may be called at any time → late init
//   • Attack: initialize() long after deployment when system should be live
//   • Defense: require initialize() within INIT_WINDOW of deployment
////////////////////////////////////////////////////////////////////////
contract InitVuln4 {
    address public owner;
    uint256 public deployedAt;

    constructor() {
        deployedAt = block.timestamp;
    }

    function initialize(address _owner) external {
        owner = _owner; // no window enforcement
    }
}

contract Attack_InitVuln4 {
    InitVuln4 public target;
    constructor(InitVuln4 _t) { target = _t; }
    function lateInit() external {
        // even after days, attacker can call initialize
        target.initialize(msg.sender);
    }
}

contract InitSafe4 {
    address public owner;
    uint256 public deployedAt;
    bool    private _inited;
    error SP__InitExpired();

    constructor() {
        deployedAt = block.timestamp;
    }

    function initialize(address _owner) external {
        if (_inited) revert SP__AlreadyInitialized();
        if (block.timestamp > deployedAt + INIT_WINDOW) revert SP__InitExpired();
        owner = _owner;
        _inited = true;
    }
}
