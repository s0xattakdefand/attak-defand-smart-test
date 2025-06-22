// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StateMachineSuite.sol
/// @notice Four on‑chain “State Machine” patterns illustrating common pitfalls
///         and hardened defenses.

error SM__BadState();
error SM__Reentered();
error SM__NotOwner();
error SM__Expired();

abstract contract NonReentrant {
    uint256 private _status;
    modifier nonReentrant() {
        if (_status == 1) revert SM__Reentered();
        _status = 1;
        _;
        _status = 0;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED TRANSITIONS
//
//   • Vulnerable: no checks on current state → any function may be called anytime
//   • Attack: call finalize() before init or without ever starting
//   • Defense: require explicit current state for each transition
////////////////////////////////////////////////////////////////////////////////
contract SaleVuln {
    enum State { Created, Active, Finalized }
    State public state;

    function start() external { state = State.Active; }
    function finalize() external { state = State.Finalized; }
    function buy() external payable { /* no state check! */ }
}

/// Demo attack: finalize immediately then buy
contract Attack_SaleVuln {
    SaleVuln public sale;
    constructor(SaleVuln _s) { sale = _s; }
    function exploit() external payable {
        sale.finalize();
        sale.buy{value: msg.value}();
    }
}

contract SaleSafe {
    enum State { Created, Active, Finalized }
    State public state;
    address public owner;

    modifier onlyState(State s) {
        if (state != s) revert SM__BadState();
        _;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert SM__NotOwner();
        _;
    }

    constructor() { owner = msg.sender; }

    function start() external onlyOwner onlyState(State.Created) {
        state = State.Active;
    }
    function buy() external payable onlyState(State.Active) {
        // accept funds
    }
    function finalize() external onlyOwner onlyState(State.Active) {
        state = State.Finalized;
        // distribute funds, etc.
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) SKIPPING STATES
//
//   • Vulnerable: allows skipping intermediate phases
//   • Attack: go from Created → Finalized without going Active
//   • Defense: enforce transitions only along adjacency map
////////////////////////////////////////////////////////////////////////////////
contract WorkflowVuln {
    uint8 public step;
    function next() external { step += 1; }
    function skipTo(uint8 s) external { step = s; }
}

/// Attack: skip steps arbitrarily
contract Attack_WorkflowVuln {
    WorkflowVuln public wf;
    constructor(WorkflowVuln _wf) { wf = _wf; }
    function skip(uint8 to) external {
        wf.skipTo(to);
    }
}

contract WorkflowSafe {
    uint8 public step;
    mapping(uint8 => mapping(uint8 => bool)) private allowed;
    address public owner;

    modifier onlyOwner() {
        if (msg.sender != owner) revert SM__NotOwner();
        _;
    }
    constructor() {
        owner = msg.sender;
        // define allowed transitions: 0→1, 1→2, 2→3
        allowed[0][1] = true;
        allowed[1][2] = true;
        allowed[2][3] = true;
    }

    function next() external onlyOwner {
        uint8 to = step + 1;
        if (!allowed[step][to]) revert SM__BadState();
        step = to;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) REENTRANT STATE UPDATE
//
//   • Vulnerable: updates state after external call → reentrancy can replay
//   • Attack: reenter before state flip to drain twice
//   • Defense: flip state before external call + nonReentrant guard
////////////////////////////////////////////////////////////////////////////////
contract VaultVuln {
    mapping(address => uint256) public balance;
    function deposit() external payable { balance[msg.sender] += msg.value; }
    function withdraw(uint256 amt) external {
        require(balance[msg.sender] >= amt);
        // ❌ state update AFTER external call
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balance[msg.sender] -= amt;
    }
}

/// Demonstrator reentrancy attack
contract Attack_VaultVuln {
    VaultVuln public vault;
    constructor(VaultVuln _v) { vault = _v; }
    receive() external payable {
        if (address(vault).balance >= msg.value) {
            vault.withdraw(msg.value);
        }
    }
    function exploit() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw(msg.value);
    }
}

contract VaultSafe is NonReentrant {
    mapping(address => uint256) public balance;
    function deposit() external payable { balance[msg.sender] += msg.value; }
    function withdraw(uint256 amt) external nonReentrant {
        require(balance[msg.sender] >= amt);
        // ✅ state update BEFORE external call
        balance[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) STUCK STATE (NO TIMEOUT)
// 
//   • Vulnerable: state machines with deadlines that never auto‑expire → stuck
//   • Attack: never call cancel or advance, contract remains in limbo
//   • Defense: enforce auto‑transition on deadline check
////////////////////////////////////////////////////////////////////////////////
contract AuctionVuln {
    enum Phase { Bidding, Closed }
    Phase public phase;
    uint256 public endTime;

    constructor(uint256 duration) {
        phase = Phase.Bidding;
        endTime = block.timestamp + duration;
    }
    function bid() external payable {
        require(phase == Phase.Bidding, "closed");
        // accept bid
    }
    function close() external {
        require(phase == Phase.Bidding, "already closed");
        phase = Phase.Closed;
    }
}

contract Attack_AuctionVuln {
    AuctionVuln public auc;
    constructor(AuctionVuln _a) { auc = _a; }
    function stall() external view {
        // attacker never calls close(), so phase stays Bidding forever
        // bids are never tallied or refunds issued
        auc.phase();
    }
}

contract AuctionSafe {
    enum Phase { Bidding, Closed }
    Phase public phase;
    uint256 public endTime;
    address public owner;

    modifier onlyOwner() {
        if (msg.sender != owner) revert SM__NotOwner();
        _;
    }

    constructor(uint256 duration) {
        owner   = msg.sender;
        phase   = Phase.Bidding;
        endTime = block.timestamp + duration;
    }

    /// @notice auto‑close if past deadline
    function _checkTimeout() internal {
        if (phase == Phase.Bidding && block.timestamp >= endTime) {
            phase = Phase.Closed;
        }
    }

    function bid() external payable {
        _checkTimeout();
        require(phase == Phase.Bidding, "closed");
        // accept bid
    }

    function close() external onlyOwner {
        _checkTimeout();
        require(phase == Phase.Bidding, "already closed");
        phase = Phase.Closed;
    }
}
