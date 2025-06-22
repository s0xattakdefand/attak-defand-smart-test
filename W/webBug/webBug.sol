// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebBugSuite.sol
/// @notice On‐chain analogues of “Web Bug” tracking patterns:
///   Types: TrackerPixel, InvisibleImage, CSSBug, JSBeacon  
///   AttackTypes: Tracking, PrivacyLeak, CSRF, SessionHijack  
///   DefenseTypes: ContentSecurityPolicy, TrackerBlocker, SameSiteCookie, RateLimit

enum WebBugType            { TrackerPixel, InvisibleImage, CSSBug, JSBeacon }
enum WebBugAttackType      { Tracking, PrivacyLeak, CSRF, SessionHijack }
enum WebBugDefenseType     { ContentSecurityPolicy, TrackerBlocker, SameSiteCookie, RateLimit }

error WB__NotAllowed();
error WB__Blocked();
error WB__NoCookie();
error WB__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE TRACKER
//    • ❌ no controls: records every visit → Tracking, PrivacyLeak
////////////////////////////////////////////////////////////////////////////////
contract WebBugVuln {
    event BugFired(
        address indexed who,
        string             url,
        WebBugType         btype,
        WebBugAttackType   attack
    );

    function fireBug(string calldata url, WebBugType btype) external {
        emit BugFired(msg.sender, url, btype, WebBugAttackType.Tracking);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates CSRF via bug and session hijack
////////////////////////////////////////////////////////////////////////////////
contract Attack_WebBug {
    WebBugVuln public target;
    string  public lastUrl;
    WebBugType public lastType;

    constructor(WebBugVuln _t) { target = _t; }

    function csrf(string calldata url) external {
        target.fireBug(url, WebBugType.CSSBug);
        lastUrl = url;
        lastType = WebBugType.CSSBug;
    }

    function hijackSession() external {
        target.fireBug(lastUrl, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH CONTENT SECURITY POLICY
//    • ✅ Defense: ContentSecurityPolicy – only allowed callers
////////////////////////////////////////////////////////////////////////////////
contract WebBugSafeCSP {
    mapping(address => bool) public allowed;
    event BugBlocked(
        address indexed who,
        string             url,
        WebBugType         btype,
        WebBugDefenseType  defense
    );
    event BugFired(
        address indexed who,
        string             url,
        WebBugType         btype,
        WebBugDefenseType  defense
    );

    constructor() {
        allowed[msg.sender] = true;
    }

    function setAllowed(address user, bool ok) external {
        require(allowed[msg.sender], "admin only");
        allowed[user] = ok;
    }

    function fireBug(string calldata url, WebBugType btype) external {
        if (!allowed[msg.sender]) {
            emit BugBlocked(msg.sender, url, btype, WebBugDefenseType.ContentSecurityPolicy);
            revert WB__NotAllowed();
        }
        emit BugFired(msg.sender, url, btype, WebBugDefenseType.ContentSecurityPolicy);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH TRACKER BLOCKER
//    • ✅ Defense: TrackerBlocker – block known bug sources
////////////////////////////////////////////////////////////////////////////////
contract WebBugSafeBlocker {
    mapping(string => bool) public blockedUrl;
    event BugBlocked(
        address indexed who,
        string             url,
        WebBugType         btype,
        WebBugDefenseType  defense
    );
    event BugFired(
        address indexed who,
        string             url,
        WebBugType         btype,
        WebBugDefenseType  defense
    );

    function setBlockedUrl(string calldata url, bool ok) external {
        // stub: open admin
        blockedUrl[url] = ok;
    }

    function fireBug(string calldata url, WebBugType btype) external {
        if (blockedUrl[url]) {
            emit BugBlocked(msg.sender, url, btype, WebBugDefenseType.TrackerBlocker);
            revert WB__Blocked();
        }
        emit BugFired(msg.sender, url, btype, WebBugDefenseType.TrackerBlocker);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SAMESITE COOKIE & RATE LIMIT
//    • ✅ Defense: SameSiteCookie – require session binding  
//               RateLimit – cap bug firings per block
////////////////////////////////////////////////////////////////////////////////
contract WebBugSafeAdvanced {
    mapping(address => bool) public sameSiteCookie;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event BugBlocked(
        address indexed who,
        string             url,
        WebBugType         btype,
        WebBugDefenseType  defense
    );
    event BugFired(
        address indexed who,
        string             url,
        WebBugType         btype,
        WebBugDefenseType  defense
    );

    error WB__NoCookie();
    error WB__TooManyRequests();

    function registerCookie(address user, bool ok) external {
        // stub: open admin
        sameSiteCookie[user] = ok;
    }

    function fireBug(string calldata url, WebBugType btype) external {
        if (!sameSiteCookie[msg.sender]) {
            emit BugBlocked(msg.sender, url, btype, WebBugDefenseType.SameSiteCookie);
            revert WB__NoCookie();
        }
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) {
            emit BugBlocked(msg.sender, url, btype, WebBugDefenseType.RateLimit);
            revert WB__TooManyRequests();
        }
        emit BugFired(msg.sender, url, btype, WebBugDefenseType.RateLimit);
    }
}
