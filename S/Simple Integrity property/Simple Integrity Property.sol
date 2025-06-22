// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

///─────────────────────────────────────────────────────────────────────────────
///                          SHARED ERRORS
///─────────────────────────────────────────────────────────────────────────────
error DI__BadChecksum();
error CI__Unauthorized();
error SI__WrongState();
error II__NoGhost();

///─────────────────────────────────────────────────────────────────────────────
/// 1) DATA INTEGRITY
///─────────────────────────────────────────────────────────────────────────────
/// Type: ensure stored data cannot be tampered after commit
/// Attack: overwrite records with malicious bytes
/// Defense: verify keccak256 checksum on store

contract DataIntegrityVuln {
    mapping(uint256 => bytes) public dataStore;
    function store(uint256 id, bytes calldata data) external {
        // ❌ no checksum enforcement
        dataStore[id] = data;
    }
}

contract Attack_DataIntegrity {
    DataIntegrityVuln public target;
    constructor(DataIntegrityVuln _t) { target = _t; }
    function tamper(uint256 id, bytes calldata malicious) external {
        // attacker simply overwrites stored data
        target.store(id, malicious);
    }
}

contract DataIntegritySafe {
    mapping(uint256 => bytes)   public dataStore;
    mapping(uint256 => bytes32) public checksum;

    function store(
        uint256 id,
        bytes calldata data,
        bytes32 sig
    ) external {
        // ✅ enforce integrity: only accept if hash matches
        if (keccak256(data) != sig) revert DI__BadChecksum();
        dataStore[id] = data;
        checksum[id]  = sig;
    }
}


///─────────────────────────────────────────────────────────────────────────────
/// 2) CONTROL INTEGRITY
///─────────────────────────────────────────────────────────────────────────────
/// Type: prevent unauthorized state changes
/// Attack: any caller can modify critical state
/// Defense: restrict to owner via require

contract ControlIntegrityVuln {
    uint256 public secret;
    function setSecret(uint256 v) external {
        // ❌ open to anyone
        secret = v;
    }
}

contract Attack_ControlIntegrity {
    ControlIntegrityVuln public target;
    constructor(ControlIntegrityVuln _t) { target = _t; }
    function pwn(uint256 v) external {
        // attacker overwrites secret
        target.setSecret(v);
    }
}

contract ControlIntegritySafe {
    uint256 public secret;
    address public owner;

    constructor() { owner = msg.sender; }

    function setSecret(uint256 v) external {
        // ✅ only owner may change
        if (msg.sender != owner) revert CI__Unauthorized();
        secret = v;
    }
}


///─────────────────────────────────────────────────────────────────────────────
/// 3) STATE INTEGRITY
///─────────────────────────────────────────────────────────────────────────────
/// Type: enforce valid state‑machine transitions
/// Attack: skip steps and go straight to final state
/// Defense: require exact prior state before moving on

enum Workflow { Init, Locked, Completed }

contract StateIntegrityVuln {
    Workflow public state;
    function toCompleted() external {
        // ❌ allows jumping from Init → Completed
        state = Workflow.Completed;
    }
}

contract Attack_StateIntegrity {
    StateIntegrityVuln public target;
    constructor(StateIntegrityVuln _t) { target = _t; }
    function skip() external {
        // attacker skips intermediate step
        target.toCompleted();
    }
}

contract StateIntegritySafe {
    Workflow public state;

    function start() external {
        // ✅ only from Init → Locked
        require(state == Workflow.Init, "bad state");
        state = Workflow.Locked;
    }

    function finish() external {
        // ✅ only from Locked → Completed
        if (state != Workflow.Locked) revert SI__WrongState();
        state = Workflow.Completed;
    }
}


///─────────────────────────────────────────────────────────────────────────────
/// 4) INVARIANT INTEGRITY
///─────────────────────────────────────────────────────────────────────────────
/// Type: maintain sum invariants between state and on‑chain balance
/// Attack: send “ghost” ETH via selfdestruct to break invariant
/// Defense: reject unknown ETH transfers via fallback revert

contract InvariantIntegrityVuln {
    mapping(address => uint256) public balance;
    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }
    function withdraw(uint256 amt) external {
        require(balance[msg.sender] >= amt, "bal");
        balance[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}

contract Attack_InvariantIntegrity {
    InvariantIntegrityVuln public target;
    constructor(InvariantIntegrityVuln _t) payable { target = _t; }
    function haunt() external {
        // send ETH via selfdestruct, bypassing deposit()
        selfdestruct(payable(address(target)));
    }
}

contract InvariantIntegritySafe {
    mapping(address => uint256) public balance;
    uint256 public total;

    /// reject any direct ETH transfers
    receive() external payable {
        revert II__NoGhost();
    }

    function deposit() external payable {
        balance[msg.sender] += msg.value;
        total += msg.value;
    }

    function withdraw(uint256 amt) external {
        require(balance[msg.sender] >= amt, "bal");
        balance[msg.sender] -= amt;
        total -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}
