// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UniformResourceLocatorSuite.sol
/// @notice On‑chain analogues of “Uniform Resource Locator” patterns:
///   Types: Absolute, Relative  
///   AttackTypes: OpenRedirect, SSRF, Injection  
///   DefenseTypes: ValidateHost, WhitelistURL, EncodeParams  

enum URLType         { Absolute, Relative }
enum URLAttackType   { OpenRedirect, SSRF, Injection }
enum URLDefenseType  { ValidateHost, WhitelistURL, EncodeParams }

error URL__BadHost();
error URL__NotAllowed();
error URL__BadInput();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE REDIRECT (no validation, default allow)
///
///    • Type: Absolute  
///    • Attack: OpenRedirect  
///    • Defense: —  
///─────────────────────────────────────────────────────────────────────────────
contract URLRedirectVuln {
    event Redirected(address indexed who, string url, URLAttackType attack);

    /// ❌ no checks on URL → anyone may redirect to arbitrary location
    function redirect(string calldata url) external {
        emit Redirected(msg.sender, url, URLAttackType.OpenRedirect);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: exploit open redirect
///
///    • AttackType: OpenRedirect  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_URLRedirect {
    URLRedirectVuln public target;
    constructor(URLRedirectVuln _t) { target = _t; }

    /// redirect users to attacker’s site
    function exploit() external {
        target.redirect("https://evil.example.com/malicious");
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE REDIRECT WITH HOST VALIDATION
///
///    • Defense: ValidateHost – only allow configured hosts  
///─────────────────────────────────────────────────────────────────────────────
contract URLRedirectSafe {
    mapping(string => bool) public allowedHosts;
    address public owner;
    event Redirected(address indexed who, string url, URLDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// only owner may whitelist hosts
    function setAllowedHost(string calldata host, bool ok) external {
        require(msg.sender == owner, "URLRedirectSafe: not owner");
        allowedHosts[host] = ok;
    }

    /// ✅ only redirect if URL’s host is whitelisted
    function redirect(string calldata url) external {
        bytes memory b = bytes(url);
        // must start with "http://" or "https://"
        require(b.length > 8, "URL too short");
        uint start;
        if (b[4]==':' && b[5]=='/' && b[6]=='/') {
            // "http://"
            start = 7;
        } else if (
            b[5]==':' && b[6]=='/' && b[7]=='/' &&
            b[0]=='h' && b[1]=='t' && b[2]=='t' && b[3]=='p' && b[4]=='s'
        ) {
            // "https://"
            start = 8;
        } else {
            revert URL__BadHost();
        }
        // extract host until next '/'
        uint i = start;
        while (i < b.length && b[i] != "/") {
            i++;
        }
        string memory host = string(slice(b, start, i - start));
        if (!allowedHosts[host]) revert URL__NotAllowed();
        emit Redirected(msg.sender, url, URLDefenseType.ValidateHost);
    }

    /// utility: slice bytes array
    function slice(bytes memory data, uint start, uint len) internal pure returns (bytes memory) {
        bytes memory out = new bytes(len);
        for (uint i = 0; i < len; i++) {
            out[i] = data[start + i];
        }
        return out;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE REDIRECT WITH PARAMETER ENCODING
///
///    • Defense: EncodeParams – reject unsafe characters in query  
///─────────────────────────────────────────────────────────────────────────────
contract URLRedirectSafeParams {
    address public owner;
    event Redirected(address indexed who, string url, URLDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// ✅ only allow ASCII alphanumerics and limited set in query params
    function redirect(string calldata baseURL, string calldata query) external {
        // simple validation: query must not contain space, quote, or script tags
        bytes memory q = bytes(query);
        for (uint i = 0; i < q.length; i++) {
            bytes1 c = q[i];
            if (
                !(c >= 0x30 && c <= 0x39) && // 0-9
                !(c >= 0x41 && c <= 0x5A) && // A-Z
                !(c >= 0x61 && c <= 0x7A) && // a-z
                c != 0x26 && // &
                c != 0x3D && // =
                c != 0x25 && // %
                c != 0x2D && // -
                c != 0x5F    // _
            ) {
                revert URL__BadInput();
            }
        }
        string memory full = string(abi.encodePacked(baseURL, "?", query));
        emit Redirected(msg.sender, full, URLDefenseType.EncodeParams);
    }
}
