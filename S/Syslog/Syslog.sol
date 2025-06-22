// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SyslogSuite.sol
/// @notice On‑chain analogues of four common “syslog” patterns:
///   1) Unauthenticated Logging  
///   2) Log Injection  
///   3) Log Flooding (DoS)  
///   4) Log Tampering  

error Syslog__Unauthorized();
error Syslog__TooManyLogs();
error Syslog__LogExists();

////////////////////////////////////////////////////////////////////////
// 1) UNAUTHENTICATED LOGGING
//
//  • Type: open logging endpoint
//  • Attack: any user can log malicious or misleading entries
//  • Defense: restrict logging to a trusted owner
////////////////////////////////////////////////////////////////////////

contract UnauthLoggingVuln {
    event Log(address indexed who, string message);

    /// ❌ anyone can emit logs
    function log(string calldata message) external {
        emit Log(msg.sender, message);
    }
}

contract Attack_UnauthLogging {
    UnauthLoggingVuln public target;
    constructor(UnauthLoggingVuln _t) { target = _t; }

    /// attacker emits misleading log
    function phish(string calldata fakeMsg) external {
        target.log(fakeMsg);
    }
}

contract UnauthLoggingSafe {
    address public owner;
    event Log(address indexed who, string message);

    constructor() {
        owner = msg.sender;
    }

    /// ✅ only owner may emit logs
    function log(string calldata message) external {
        if (msg.sender != owner) revert Syslog__Unauthorized();
        emit Log(msg.sender, message);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) LOG INJECTION
//
//  • Type: logs include raw user input
//  • Attack: inject control sequences or misleading text
//  • Defense: emit only hashes or sanitized data
////////////////////////////////////////////////////////////////////////

contract InjectionLoggingVuln {
    event RawLog(string message);

    /// ❌ logs raw input
    function log(string calldata message) external {
        emit RawLog(message);
    }
}

contract Attack_LogInjection {
    InjectionLoggingVuln public target;
    constructor(InjectionLoggingVuln _t) { target = _t; }

    /// attacker injects malicious payload
    function inject() external {
        target.log("NormalMessage; DELETE ALL LOGS;");
    }
}

contract InjectionLoggingSafe {
    event SafeLog(bytes32 messageHash);

    /// ✅ log only hash of input
    function log(string calldata message) external {
        emit SafeLog(keccak256(bytes(message)));
    }
}

////////////////////////////////////////////////////////////////////////
// 3) LOG FLOODING (DoS)
//
//  • Type: no rate‑limit on logging
//  • Attack: spam logs to exhaust gas or clutter audit
//  • Defense: enforce per‑user rate limits
////////////////////////////////////////////////////////////////////////

contract FloodLoggingVuln {
    event FloodLog(address indexed who, string message);

    /// ❌ unlimited logs
    function flood(string calldata message) external {
        emit FloodLog(msg.sender, message);
    }
}

contract Attack_LogFlooding {
    FloodLoggingVuln public target;
    constructor(FloodLoggingVuln _t) { target = _t; }

    /// attacker spams n logs
    function spam(uint256 n, string calldata message) external {
        for (uint256 i; i < n; ++i) {
            target.flood(message);
        }
    }
}

contract FloodLoggingSafe {
    event FloodLog(address indexed who, string message);

    uint256 public constant MAX_PER_WINDOW = 5;
    uint256 public constant WINDOW = 60; // seconds

    mapping(address => uint256) public count;
    mapping(address => uint256) public windowStart;

    /// ✅ limit to MAX_PER_WINDOW logs per WINDOW seconds
    function flood(string calldata message) external {
        uint256 start = windowStart[msg.sender];
        if (block.timestamp > start + WINDOW) {
            windowStart[msg.sender] = block.timestamp;
            count[msg.sender] = 0;
        }
        count[msg.sender] += 1;
        if (count[msg.sender] > MAX_PER_WINDOW) revert Syslog__TooManyLogs();
        emit FloodLog(msg.sender, message);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) LOG TAMPERING
//
//  • Type: on‑chain storage of logs that can be overwritten
//  • Attack: attacker overwrites or deletes existing logs
//  • Defense: write‑once (append‑only) storage
////////////////////////////////////////////////////////////////////////

contract TamperLoggingVuln {
    mapping(uint256 => string) public logs;

    /// ❌ allows overwriting any log entry
    function write(uint256 id, string calldata message) external {
        logs[id] = message;
    }
}

contract Attack_LogTampering {
    TamperLoggingVuln public target;
    constructor(TamperLoggingVuln _t) { target = _t; }

    /// attacker overwrites victim’s log
    function tamper(uint256 id, string calldata fakeMessage) external {
        target.write(id, fakeMessage);
    }
}

contract TamperLoggingSafe {
    mapping(uint256 => string) public logs;
    event LogWritten(uint256 indexed id, string message);

    /// ✅ only allow write‑once per id
    function write(uint256 id, string calldata message) external {
        if (bytes(logs[id]).length != 0) revert Syslog__LogExists();
        logs[id] = message;
        emit LogWritten(id, message);
    }
}
