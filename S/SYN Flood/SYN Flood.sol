// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SynFloodSuite.sol
/// @notice On‑chain analogues of four SYN‑Flood patterns and defenses:
///   1) Half‑Open Session Leak  
///   2) Per‑Address Flooding  
///   3) Cookieless Handshake  
///   4) Global Session Exhaustion  

error SF__TooManyHalfOpen();
error SF__TooManyPerUser();
error SF__BadCookie();
error SF__TooManyGlobal();
error SF__SessionNotFound();

////////////////////////////////////////////////////////////////////////
// 1) HALF‑OPEN SESSION LEAK
//
//  • Type: startSession() never cleaned up → indefinite half‑opens
//  • Attack: call startSession() repeatedly to leak storage
//  • Defense: expire half‑opens after timeout
////////////////////////////////////////////////////////////////////////
contract HalfOpenVuln {
    mapping(address => uint256[]) public halfOpens;

    /// ❌ starts a “session” but never finishes or expires
    function startSession() external {
        halfOpens[msg.sender].push(block.timestamp);
    }
}

contract Attack_HalfOpen {
    HalfOpenVuln public target;
    constructor(HalfOpenVuln _t) { target = _t; }
    function flood(uint n) external {
        for (uint i; i < n; ++i) {
            target.startSession();
        }
    }
}

contract HalfOpenSafe {
    struct Session { uint256 start; bool open; }
    mapping(address => Session[]) public halfOpens;
    uint256 public immutable TIMEOUT = 5 minutes;

    /// ✅ start and expire old half‑opens
    function startSession() external {
        Session[] storage arr = halfOpens[msg.sender];
        // expire any stale sessions
        uint write;
        for (uint read; read < arr.length; ++read) {
            if (block.timestamp - arr[read].start < TIMEOUT && arr[read].open) {
                arr[write++] = arr[read];
            }
        }
        while (arr.length > write) arr.pop();
        // record new half‑open
        arr.push(Session({ start: block.timestamp, open: true }));
    }

    /// must call to complete and free storage
    function completeSession(uint idx) external {
        Session storage s = halfOpens[msg.sender][idx];
        require(s.open, "no session");
        s.open = false;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) PER‑ADDRESS FLOODING
//
//  • Type: unlimited startSession per address → DoS per user
//  • Attack: one address calls startSession() many times
//  • Defense: cap sessions per address
////////////////////////////////////////////////////////////////////////
contract RateLimitVuln {
    mapping(address => uint256) public count;
    function startSession() external {
        // ❌ no limit
        count[msg.sender] += 1;
    }
}

contract Attack_RateLimit {
    RateLimitVuln public target;
    constructor(RateLimitVuln _t) { target = _t; }
    function flood(uint n) external {
        for (uint i; i < n; ++i) {
            target.startSession();
        }
    }
}

contract RateLimitSafe {
    mapping(address => uint256) public count;
    uint256 public constant MAX_PER_USER = 10;

    function startSession() external {
        if (count[msg.sender] >= MAX_PER_USER) revert SF__TooManyPerUser();
        count[msg.sender] += 1;
    }

    function endSession() external {
        require(count[msg.sender] > 0, "none");
        count[msg.sender] -= 1;
    }
}

////////////////////////////////////////////////////////////////////////
// 3) COOKIELESS HANDSHAKE
//
//  • Type: accept any startHandshake() → easy spoofing & flooding
//  • Attack: call startHandshake() without proof
//  • Defense: require a signed cookie
////////////////////////////////////////////////////////////////////////
library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes memory sig) internal pure returns (address a) {
        require(sig.length == 65, "bad length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0, mload(add(sig,96)))
        }
        a = ecrecover(h, v, r, s);
        require(a != address(0), "invalid sig");
    }
}

contract CookieVuln {
    mapping(address => bool) public handshakes;
    function startHandshake() external {
        // ❌ no proof required
        handshakes[msg.sender] = true;
    }
}

contract Attack_Cookie {
    CookieVuln public target;
    constructor(CookieVuln _t) { target = _t; }
    function flood(uint n) external {
        for (uint i; i < n; ++i) {
            target.startHandshake();
        }
    }
}

contract CookieSafe {
    using ECDSA for bytes32;
    address public immutable signer;
    mapping(address => bool) public handshakes;
    mapping(bytes32 => bool) public usedCookie;

    error SF__BadCookie();
    error SF__CookieUsed();

    constructor(address _signer) {
        signer = _signer;
    }

    /// @param cookie  a random 32‑byte value signed by `signer`
    /// @param sig     signature over keccak256(msg.sender‖cookie)
    function startHandshake(bytes32 cookie, bytes calldata sig) external {
        if (usedCookie[cookie]) revert SF__CookieUsed();
        bytes32 h = keccak256(abi.encodePacked(msg.sender, cookie))
            .toEthSignedMessageHash();
        if (h.recover(sig) != signer) revert SF__BadCookie();

        usedCookie[cookie] = true;
        handshakes[msg.sender] = true;
    }
}

////////////////////////////////////////////////////////////////////////
// 4) GLOBAL SESSION EXHAUSTION
//
//  • Type: unlimited total sessions → global DoS
//  • Attack: many users call startSession()
//  • Defense: cap global sessions
////////////////////////////////////////////////////////////////////////
contract GlobalLimitVuln {
    uint256 public total;
    function startSession() external {
        // ❌ no global cap
        total += 1;
    }
}

contract Attack_GlobalLimit {
    GlobalLimitVuln public target;
    constructor(GlobalLimitVuln _t) { target = _t; }
    function flood(uint n) external {
        for (uint i; i < n; ++i) {
            target.startSession();
        }
    }
}

contract GlobalLimitSafe {
    uint256 public total;
    uint256 public constant MAX_GLOBAL = 1000;

    function startSession() external {
        if (total + 1 > MAX_GLOBAL) revert SF__TooManyGlobal();
        total += 1;
    }

    function endSession() external {
        require(total > 0, "none");
        total -= 1;
    }
}
