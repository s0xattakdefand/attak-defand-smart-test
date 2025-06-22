// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StackMashingSuite.sol
/// @notice Four “Stack Mashing” patterns illustrating common pitfalls in EVM stack/memory usage
///         and hardened defenses.

error SM__OOB();               // Out‑of‑bounds memory write
error SM__RecursionTooDeep();  // Excessive recursion
error SM__DelegateForbidden(); // Delegatecall not allowed
error SM__DepthExceeded();     // Call depth too great

////////////////////////////////////////////////////////////////////////////////
// 1) UNCHECKED MEMORY WRITE (STACK‑SMASH ANALOGUE)
//    • Vulnerable: assembly allows writing past allocated memory
//    • Attack: write beyond the 2‑slot array, clobber unrelated memory
//    • Defense: bound‑check before writing
////////////////////////////////////////////////////////////////////////////////
contract MemoryOverflowVuln {
    /// writes `val` into the `index`th slot of a 2‑element memory array
    function write(uint256 index, uint256 val) external pure returns (uint256[2] memory) {
        uint256[2] memory buf;
        assembly {
            // ❌ no bounds check: mem pointer + index*0x20 can be out‑of‑bounds
            let ptr := add(buf, mul(index, 0x20))
            mstore(ptr, val)
        }
        return buf;
    }
}

contract Attack_MemoryOverflow {
    MemoryOverflowVuln public target;
    constructor(MemoryOverflowVuln _t) { target = _t; }

    /// calls with index=2 to overwrite buf[2], smashing beyond the 2‑element array
    function smash(uint256 val) external pure returns (uint256[2] memory) {
        return MemoryOverflowVuln(address(0)).write(2, val);
    }
}

contract MemoryOverflowSafe {
    function write(uint256 index, uint256 val) external pure returns (uint256[2] memory) {
        if (index >= 2) revert SM__OOB();
        uint256[2] memory buf;
        assembly {
            let ptr := add(buf, mul(index, 0x20))
            mstore(ptr, val)
        }
        return buf;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) INFINITE RECURSION (STACK DEPTH EXHAUSTION)
//    • Vulnerable: no base case → unbounded call stack until OOG or depth error
//    • Attack: call with any value to trigger runaway recursion
//    • Defense: enforce a maximum recursion depth
////////////////////////////////////////////////////////////////////////////////
contract RecursionVuln {
    function runaway(uint256 depth) external {
        // ❌ no base case: always recurses
        this.runaway(depth + 1);
    }
}

contract Attack_Recursion {
    RecursionVuln public target;
    constructor(RecursionVuln _t) { target = _t; }

    /// simply calls runaway to trigger stack/OG
    function trigger() external {
        target.runaway(0);
    }
}

contract RecursionSafe {
    uint256 public constant MAX_DEPTH = 50;

    function runaway(uint256 depth) external {
        if (depth > MAX_DEPTH) revert SM__RecursionTooDeep();
        if (depth < MAX_DEPTH) {
            // ✅ only recuse while depth < limit
            this.runaway(depth + 1);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) DELEGATECALL STACK HIJACK
//    • Vulnerable: delegatecall into untrusted module corrupts caller’s stack/storage
//    • Attack: malicious module clears essential state
//    • Defense: avoid delegatecall or whitelist modules
////////////////////////////////////////////////////////////////////////////////
contract DelegateStackVuln {
    address public module;
    uint256 public important = 0x1234;

    function setModule(address m) external {
        module = m;
    }

    function exec(bytes calldata data) external {
        // ❌ delegatecall reuses this contract’s context
        (bool ok, ) = module.delegatecall(data);
        require(ok, "delegate failed");
    }
}

contract Attack_DelegateStack {
    // fallback invoked via delegatecall: zeroes out slot 1 (`important`)
    fallback() external {
        assembly { sstore(1, 0) }
    }
}

contract DelegateStackSafe {
    address public module;
    address public owner;
    uint256 public important = 0x1234;

    error SM__NotAllowed();

    constructor() { owner = msg.sender; }

    function setModule(address m) external {
        if (msg.sender != owner) revert SM__NotAllowed();
        module = m;
    }

    function exec(bytes calldata data) external {
        if (msg.sender != owner) revert SM__NotAllowed();
        // ✅ use regular call: callee cannot modify caller’s state
        (bool ok, ) = module.call(data);
        require(ok, "call failed");
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) CALL DEPTH DOS (CALL STACK LIMIT)
//    • Vulnerable: unchecked external recursion until EVM call depth limit (~1024)
//    • Attack: ask for large depth, causing revert at a deep call
//    • Defense: cap the requested depth
////////////////////////////////////////////////////////////////////////////////
contract CallDepthVuln {
    function depth(uint256 d) external {
        if (d == 0) return;
        // ❌ uncontrolled: each external call consumes a stack frame
        this.depth(d - 1);
    }
}

contract Attack_CallDepth {
    CallDepthVuln public target;
    constructor(CallDepthVuln _t) { target = _t; }

    function dos() external {
        // triggers depth until revert
        target.depth(2000);
    }
}

contract CallDepthSafe {
    uint256 public constant MAX_CALL_DEPTH = 500;

    function depth(uint256 d) external {
        if (d > MAX_CALL_DEPTH) revert SM__DepthExceeded();
        if (d > 0) {
            this.depth(d - 1);
        }
    }
}
