// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StoreAndForwardSuite.sol
/// @notice Four “Store‑And‑Forward” patterns, each with a vulnerable module, an attack stub,
///         and a hardened defense module enforcing proper controls.

////////////////////////////////////////////////////////////////////////
// Shared Errors
////////////////////////////////////////////////////////////////////////
error SF__NotOwner();
error SF__Replayed();
error SF__QueueFull();
error SF__TargetNotAllowed();

////////////////////////////////////////////////////////////////////////
// 1) UNAUTHENTICATED STORE‑AND‑FORWARD
//    • Type: anyone can enqueue arbitrary calls
//    • Attack: enqueue a malicious self‑destruct payload
//    • Defense: restrict enqueue to owner only
////////////////////////////////////////////////////////////////////////
contract StoreForwardVuln1 {
    struct Msg { address target; bytes data; }
    Msg[] public queue;

    function enqueue(address target, bytes calldata data) external {
        queue.push(Msg(target, data));
    }

    function forwardAll() external {
        for (uint i; i < queue.length; i++) {
            (bool ok, ) = queue[i].target.call(queue[i].data);
            require(ok, "forward failed");
        }
    }
}

/// Attack: poison the queue with a self‑destruct payload
contract Attack_StoreForward1 {
    StoreForwardVuln1 public vf;
    constructor(StoreForwardVuln1 _vf) { vf = _vf; }
    function hijack() external {
        // encode: selfdestruct(payable(attacker))
        bytes memory p = abi.encodeWithSignature("selfdestruct(address)", msg.sender);
        vf.enqueue(address(vf), p);
        vf.forwardAll();
    }
}

contract StoreForwardSafe1 {
    address public owner;
    struct Msg { address target; bytes data; }
    Msg[] public queue;

    modifier onlyOwner() {
        if (msg.sender != owner) revert SF__NotOwner();
        _;
    }

    constructor() { owner = msg.sender; }

    function enqueue(address target, bytes calldata data) external onlyOwner {
        queue.push(Msg(target, data));
    }

    function forwardAll() external onlyOwner {
        for (uint i; i < queue.length; i++) {
            (bool ok, ) = queue[i].target.call(queue[i].data);
            require(ok, "forward failed");
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 2) REPLAYABLE STORE‑AND‑FORWARD
//    • Type: messages can be forwarded multiple times
//    • Attack: call forward(id) twice to replay
//    • Defense: mark messages as forwarded
////////////////////////////////////////////////////////////////////////
contract StoreForwardVuln2 {
    struct Msg { address target; bytes data; }
    Msg[] public queue;

    function enqueue(address target, bytes calldata data) external {
        queue.push(Msg(target, data));
    }

    function forward(uint index) external {
        Msg storage m = queue[index];
        (bool ok, ) = m.target.call(m.data);
        require(ok, "forward failed");
    }
}

/// Attack: replay forward on the same index twice
contract Attack_StoreForward2 {
    StoreForwardVuln2 public vf;
    uint public idx;
    constructor(StoreForwardVuln2 _vf, uint _idx) { vf = _vf; idx = _idx; }
    function replay() external {
        vf.forward(idx);
        vf.forward(idx); // succeeds again
    }
}

contract StoreForwardSafe2 {
    struct Msg { address target; bytes data; bool done; }
    Msg[] public queue;
    error SF__Replayed();

    function enqueue(address target, bytes calldata data) external {
        queue.push(Msg(target, data, false));
    }

    function forward(uint index) external {
        Msg storage m = queue[index];
        if (m.done) revert SF__Replayed();
        (bool ok, ) = m.target.call(m.data);
        require(ok, "forward failed");
        m.done = true;
    }
}

////////////////////////////////////////////////////////////////////////
// 3) UNBOUNDED QUEUE (DOS)
//    • Type: unlimited enqueue → queue grows unbounded
//    • Attack: flood queue to exhaust gas/storage
//    • Defense: cap queue length
////////////////////////////////////////////////////////////////////////
contract StoreForwardVuln3 {
    struct Msg { address target; bytes data; }
    Msg[] public queue;

    function enqueue(address target, bytes calldata data) external {
        queue.push(Msg(target, data));
    }
}

contract Attack_StoreForward3 {
    StoreForwardVuln3 public vf;
    constructor(StoreForwardVuln3 _vf) { vf = _vf; }
    function flood(address target, bytes calldata data, uint n) external {
        for (uint i; i < n; i++) {
            vf.enqueue(target, data);
        }
    }
}

contract StoreForwardSafe3 {
    struct Msg { address target; bytes data; }
    Msg[] public queue;
    uint public constant MAX_QUEUE = 100;
    error SF__QueueFull();

    function enqueue(address target, bytes calldata data) external {
        if (queue.length >= MAX_QUEUE) revert SF__QueueFull();
        queue.push(Msg(target, data));
    }
}

////////////////////////////////////////////////////////////////////////
// 4) UNAUTHORIZED TARGET EXECUTION
//    • Type: arbitrary targets allowed → malicious calls permitted
//    • Attack: forward to disallowed address (e.g., self)
//    • Defense: whitelist allowed targets
////////////////////////////////////////////////////////////////////////
contract StoreForwardVuln4 {
    struct Msg { address target; bytes data; }
    Msg[] public queue;

    function enqueue(address target, bytes calldata data) external {
        queue.push(Msg(target, data));
    }

    function forwardAll() external {
        for (uint i; i < queue.length; i++) {
            (bool ok, ) = queue[i].target.call(queue[i].data);
            require(ok, "forward failed");
        }
    }
}

contract Attack_StoreForward4 {
    StoreForwardVuln4 public vf;
    constructor(StoreForwardVuln4 _vf) { vf = _vf; }
    function hijack() external {
        // call attacker contract instead of intended target
        bytes memory p = abi.encodeWithSignature("malicious()");
        vf.enqueue(address(this), p);
        vf.forwardAll();
    }
    function malicious() external {
        // attacker logic
    }
}

contract StoreForwardSafe4 {
    address public owner;
    mapping(address => bool) public allowedTargets;
    struct Msg { address target; bytes data; }
    Msg[] public queue;
    error SF__TargetNotAllowed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert SF__NotOwner();
        _;
    }

    constructor() { owner = msg.sender; }

    function setAllowed(address target, bool ok) external onlyOwner {
        allowedTargets[target] = ok;
    }

    function enqueue(address target, bytes calldata data) external {
        if (!allowedTargets[target]) revert SF__TargetNotAllowed();
        queue.push(Msg(target, data));
    }

    function forwardAll() external {
        for (uint i; i < queue.length; i++) {
            (bool ok, ) = queue[i].target.call(queue[i].data);
            require(ok, "forward failed");
        }
    }
}
