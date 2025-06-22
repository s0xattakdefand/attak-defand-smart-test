// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Shared errors
error Policy__NotWhitelisted();
error Policy__Blacklisted();
error Policy__RateLimitExceeded();
error Policy__AccessNotAllowed();

/// @title 1. Whitelist Policy
contract WhitelistVuln {
    mapping(address => bool) public whitelisted;
    event ProtectedCalled(address who);

    constructor() { /* empty */ }

    // ❌ No whitelist check!
    function protectedAction() external {
        emit ProtectedCalled(msg.sender);
    }

    function addToWhitelist(address who) external {
        whitelisted[who] = true;
    }
}

/// Attack bypassing whitelist
contract Attack_WhitelistBypass {
    WhitelistVuln public target;
    constructor(WhitelistVuln _t) { target = _t; }
    function exploit() external {
        target.protectedAction(); // succeeds even if not whitelisted
    }
}

contract WhitelistSafe {
    mapping(address => bool) public whitelisted;
    event ProtectedCalled(address who);

    constructor(address[] memory initial) {
        for (uint i; i < initial.length; i++) {
            whitelisted[initial[i]] = true;
        }
    }

    function protectedAction() external {
        if (!whitelisted[msg.sender]) revert Policy__NotWhitelisted();
        emit ProtectedCalled(msg.sender);
    }

    function addToWhitelist(address who) external {
        whitelisted[who] = true;
    }
}


/// @title 2. Blacklist Policy
contract BlacklistVuln {
    mapping(address => bool) public blacklisted;
    event ProtectedCalled(address who);

    constructor() { /* empty */ }

    // ❌ No blacklist check!
    function protectedAction() external {
        emit ProtectedCalled(msg.sender);
    }

    function addToBlacklist(address who) external {
        blacklisted[who] = true;
    }
}

/// Attack using blacklisted address
contract Attack_BlacklistBypass {
    BlacklistVuln public target;
    constructor(BlacklistVuln _t) { target = _t; }
    function exploit() external {
        target.protectedAction(); // even if blacklisted, succeeds
    }
}

contract BlacklistSafe {
    mapping(address => bool) public blacklisted;
    event ProtectedCalled(address who);

    constructor(address[] memory initial) {
        for (uint i; i < initial.length; i++) {
            blacklisted[initial[i]] = true;
        }
    }

    function protectedAction() external {
        if (blacklisted[msg.sender]) revert Policy__Blacklisted();
        emit ProtectedCalled(msg.sender);
    }

    function addToBlacklist(address who) external {
        blacklisted[who] = true;
    }
}


/// @title 3. Rate‑Limit Policy
contract RateLimitVuln {
    uint256 public count;
    event ProtectedCalled(address who, uint256 cnt);

    // ❌ No rate‐limit → anyone can spam
    function protectedAction() external {
        unchecked { count++; }
        emit ProtectedCalled(msg.sender, count);
    }
}

/// Attack flooding the contract
contract Attack_RateLimitFlood {
    RateLimitVuln public target;
    constructor(RateLimitVuln _t) { target = _t; }
    function exploit(uint256 times) external {
        for (uint i; i < times; i++) {
            target.protectedAction();
        }
    }
}

contract RateLimitSafe {
    uint256 public constant WINDOW = 1 hours;
    uint256 public constant MAX_CALLS = 10;

    struct Info { uint32 windowStart; uint32 calls; }
    mapping(address => Info) public usage;
    event ProtectedCalled(address who, uint256 thisWindowCalls);

    function protectedAction() external {
        Info storage info = usage[msg.sender];
        uint32 ts = uint32(block.timestamp);
        // reset window if expired
        if (ts > info.windowStart + WINDOW) {
            info.windowStart = ts;
            info.calls = 0;
        }
        unchecked {
            info.calls++;
            if (info.calls > MAX_CALLS) revert Policy__RateLimitExceeded();
        }
        emit ProtectedCalled(msg.sender, info.calls);
    }
}


/// @title 4. Time‑Access Policy
contract TimePolicyVuln {
    event ProtectedCalled(address who, uint256 ts);

    // ❌ No time restriction at all
    function protectedAction() external {
        emit ProtectedCalled(msg.sender, block.timestamp);
    }
}

/// Attack at any time
contract Attack_TimePolicyBypass {
    TimePolicyVuln public target;
    constructor(TimePolicyVuln _t) { target = _t; }
    function exploit() external {
        target.protectedAction(); // always succeeds
    }
}

contract TimePolicySafe {
    uint8 public startHour; // inclusive [0–23]
    uint8 public endHour;   // exclusive [1–24]
    event ProtectedCalled(address who, uint256 ts);

    constructor(uint8 _startHour, uint8 _endHour) {
        startHour = _startHour;
        endHour   = _endHour;
    }

    function protectedAction() external {
        uint256 secsInDay = block.timestamp % 86400;
        uint8 hour = uint8(secsInDay / 3600);
        if (hour < startHour || hour >= endHour) revert Policy__AccessNotAllowed();
        emit ProtectedCalled(msg.sender, block.timestamp);
    }
}
