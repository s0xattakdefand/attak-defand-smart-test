// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StimulusSuite.sol
/// @notice Four “Stimulus” patterns illustrating common pitfalls and hardened defenses:
///   1) Unauthenticated Stimulus  
///   2) Stimulus Flooding (DoS)  
///   3) Stimulus Injection (Log Injection)  
///   4) Stimulus‑Triggered Reentrancy  

error Stim__NotOwner();
error Stim__TooMany();
error Stim__BadPayload();
error Stim__Reentrant();

/// Simple non‑reentrancy guard
abstract contract NonReentrant {
    uint256 private _status;
    modifier nonReentrant() {
        if (_status == 1) revert Stim__Reentrant();
        _status = 1;
        _;
        _status = 0;
    }
}

////////////////////////////////////////////////////////////////////////
// 1) UNAUTHENTICATED STIMULUS
//
//   • Vulnerable: anyone can trigger state changes
//   • Attack: unauthorized caller invokes `sendStimulus`
//   • Defense: restrict to owner only
////////////////////////////////////////////////////////////////////////
contract StimulusVuln1 {
    mapping(uint256 => uint256) public data;

    /// anyone may call → unauthorized stimulus
    function sendStimulus(uint256 id, uint256 value) external {
        data[id] = value;
    }
}

contract Attack_Stimulus1 {
    StimulusVuln1 public target;
    constructor(StimulusVuln1 _t) { target = _t; }
    function hijack(uint256 id, uint256 val) external {
        // attacker triggers stimulus
        target.sendStimulus(id, val);
    }
}

contract StimulusSafe1 {
    address public owner;
    mapping(uint256 => uint256) public data;
    error Stim__NotAuthorized();

    constructor() { owner = msg.sender; }

    /// only owner may send stimulus
    function sendStimulus(uint256 id, uint256 value) external {
        if (msg.sender != owner) revert Stim__NotAuthorized();
        data[id] = value;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) STIMULUS FLOODING (DoS)
//
//   • Vulnerable: bulkStimulus accepts unbounded arrays → DoS
//   • Attack: pass huge arrays to exhaust gas
//   • Defense: enforce MAX_BULK limit
////////////////////////////////////////////////////////////////////////
contract StimulusVuln2 {
    mapping(uint256 => uint256) public data;

    function bulkStimulus(
        uint256[] calldata ids,
        uint256[] calldata values
    ) external {
        for (uint i; i < ids.length; i++) {
            data[ids[i]] = values[i];
        }
    }
}

contract Attack_Stimulus2 {
    StimulusVuln2 public target;
    constructor(StimulusVuln2 _t) { target = _t; }

    function flood(
        uint256[] calldata ids,
        uint256[] calldata vals
    ) external {
        // attacker floods with large arrays
        target.bulkStimulus(ids, vals);
    }
}

contract StimulusSafe2 {
    mapping(uint256 => uint256) public data;
    uint256 public constant MAX_BULK = 50;
    error Stim__TooMany();

    function bulkStimulus(
        uint256[] calldata ids,
        uint256[] calldata values
    ) external {
        if (ids.length > MAX_BULK) revert Stim__TooMany();
        for (uint i; i < ids.length; i++) {
            data[ids[i]] = values[i];
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) STIMULUS INJECTION (LOG INJECTION)
//
//   • Vulnerable: logs raw payload → off‑chain log injection
//   • Attack: emit misleading messages
//   • Defense: emit only hash of payload
////////////////////////////////////////////////////////////////////////
contract StimulusVuln3 {
    event StimulusLogged(address indexed who, string payload);

    function logStimulus(string calldata payload) external {
        emit StimulusLogged(msg.sender, payload);
    }
}

contract Attack_Stimulus3 {
    StimulusVuln3 public target;
    constructor(StimulusVuln3 _t) { target = _t; }
    function inject(string calldata msg_) external {
        // attacker injects malicious log
        target.logStimulus(msg_);
    }
}

contract StimulusSafe3 {
    event StimulusLogged(address indexed who, bytes32 payloadHash);
    error Stim__BadPayload();

    function logStimulus(string calldata payload) external {
        if (bytes(payload).length > 256) revert Stim__BadPayload();
        emit StimulusLogged(msg.sender, keccak256(bytes(payload)));
    }
}

////////////////////////////////////////////////////////////////////////
// 4) STIMULUS‑TRIGGERED REENTRANCY
//
//   • Vulnerable: processing stimulus sends ETH before state update
//   • Attack: re‑enter in fallback to drain funds
//   • Defense: nonReentrant guard, update state first
////////////////////////////////////////////////////////////////////////
contract StimulusVuln4 {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    /// ❌ vulnerable: sends ETH then updates balance
    function withdraw(uint256 amt) external {
        require(balance[msg.sender] >= amt, "insufficient");
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "transfer failed");
        balance[msg.sender] -= amt;
    }
}

contract Attack_Stimulus4 {
    StimulusVuln4 public target;
    constructor(StimulusVuln4 _t) { target = _t; }

    receive() external payable {
        if (address(target).balance >= msg.value) {
            // re‑enter to drain more
            target.withdraw(msg.value);
        }
    }

    function exploit() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
}

contract StimulusSafe4 is NonReentrant {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    /// ✅ nonReentrant + update state before external call
    function withdraw(uint256 amt) external nonReentrant {
        require(balance[msg.sender] >= amt, "insufficient");
        balance[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "transfer failed");
    }
}
