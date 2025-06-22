// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CookieSuite.sol
/// @notice On-chain analogues of “Cookies” client-side storage patterns:
///   Types: Session, Persistent  
///   AttackTypes: XSS, CSRF, SessionHijack  
///   DefenseTypes: HttpOnlyFlag, SecureFlag, SameSiteStrict, Encryption  

enum CookieType           { Session, Persistent }
enum CookieAttackType     { XSS, CSRF, SessionHijack }
enum CookieDefenseType    { HttpOnlyFlag, SecureFlag, SameSiteStrict, Encryption }

error CK__NotOwner();
error CK__Unauthorized();
error CK__NoHttp();
error CK__BadSite();
error CK__BadKey();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE COOKIE JAR
//
//    • no flags, cookies readable & writable by any caller → XSS, CSRF
////////////////////////////////////////////////////////////////////////
contract CookieVuln {
    mapping(address => mapping(string => string)) public jar;
    event CookieSet(
        address indexed who,
        CookieType     ctype,
        string         name,
        string         value,
        CookieAttackType attack
    );
    event CookieRead(
        address indexed who,
        CookieType     ctype,
        string         name,
        string         value,
        CookieAttackType attack
    );

    function setCookie(CookieType ctype, string calldata name, string calldata value) external {
        jar[msg.sender][name] = value;
        emit CookieSet(msg.sender, ctype, name, value, CookieAttackType.CSRF);
    }

    function readCookie(address user, CookieType ctype, string calldata name) external {
        string memory val = jar[user][name];
        emit CookieRead(msg.sender, ctype, name, val, CookieAttackType.XSS);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • XSS: read victim’s cookies  
//    • CSRF: set cookie on victim
////////////////////////////////////////////////////////////////////////
contract Attack_Cookie {
    CookieVuln public target;
    constructor(CookieVuln _t) { target = _t; }

    function steal(address victim, CookieType ctype, string calldata name) external {
        target.readCookie(victim, ctype, name);
    }

    function forge(string calldata name, string calldata value) external {
        target.setCookie(CookieType.Session, name, value);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH HTTPONLY FLAG
//
//    • Defense: HttpOnlyFlag – cookies only writable/readable on-chain by owner
////////////////////////////////////////////////////////////////////////
contract CookieSafeHttpOnly {
    mapping(address => mapping(string => string)) private jar;
    event CookieSet(
        address indexed who,
        CookieType     ctype,
        string         name,
        CookieDefenseType defense
    );

    error CK__NoHttp();

    function setCookie(CookieType ctype, string calldata name, string calldata value) external {
        jar[msg.sender][name] = value;
        emit CookieSet(msg.sender, ctype, name, CookieDefenseType.HttpOnlyFlag);
    }

    function readCookie(string calldata name) external view returns (string memory) {
        // HttpOnly: only contract call by owner
        return jar[msg.sender][name];
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH SECURE & SAMESITE STRICT
//
//    • Defense: SecureFlag – only allow on-chain “https” calls (simulated)  
//               SameSiteStrict – only same-origin reads
////////////////////////////////////////////////////////////////////////
contract CookieSafeSecureSameSite {
    mapping(address => mapping(string => string)) public jar;
    mapping(address => string) public origin;
    event CookieSet(
        address indexed who,
        CookieType     ctype,
        string         name,
        CookieDefenseType defense
    );
    event CookieRead(
        address indexed who,
        CookieType     ctype,
        string         name,
        CookieDefenseType defense
    );

    error CK__BadSite();

    function setOrigin(string calldata site) external {
        origin[msg.sender] = site;
    }

    function setCookie(CookieType ctype, string calldata name, string calldata value, string calldata site) external {
        // Secure: require https prefix
        require(bytes(site).length >= 8 && keccak256(bytes(site[:5])) == keccak256("https"), "insecure");
        jar[msg.sender][name] = value;
        emit CookieSet(msg.sender, ctype, name, CookieDefenseType.SecureFlag);
    }

    function readCookie(address user, CookieType ctype, string calldata name, string calldata site) external {
        // SameSiteStrict: only allow if site matches owner’s origin
        if (keccak256(bytes(site)) != keccak256(bytes(origin[user]))) revert CK__BadSite();
        emit CookieRead(msg.sender, ctype, name, CookieDefenseType.SameSiteStrict);
    }
}

////////////////////////////////////////////////////////////////////////
// 5) SAFE WITH ENCRYPTION
//
//    • Defense: Encryption – store encrypted, require key to decrypt
////////////////////////////////////////////////////////////////////////
contract CookieSafeEncrypted {
    mapping(address => mapping(string => bytes)) private jar;
    mapping(address => bytes32) public key;
    event CookieSet(
        address indexed who,
        CookieType     ctype,
        string         name,
        CookieDefenseType defense
    );
    event CookieRead(
        address indexed who,
        CookieType     ctype,
        string         name,
        string         value,
        CookieDefenseType defense
    );

    error CK__BadKey();

    function registerKey(bytes32 k) external {
        key[msg.sender] = k;
    }

    function setCookie(CookieType ctype, string calldata name, string calldata value) external {
        bytes32 k = key[msg.sender];
        require(k != bytes32(0), "no key");
        bytes memory plain = bytes(value);
        bytes memory ct = new bytes(plain.length);
        for (uint i = 0; i < plain.length; i++) {
            ct[i] = plain[i] ^ k[i % 32];
        }
        jar[msg.sender][name] = ct;
        emit CookieSet(msg.sender, ctype, name, CookieDefenseType.Encryption);
    }

    function readCookie(string calldata name) external {
        bytes32 k = key[msg.sender];
        if (k == bytes32(0)) revert CK__BadKey();
        bytes memory ct = jar[msg.sender][name];
        bytes memory pt = new bytes(ct.length);
        for (uint i = 0; i < ct.length; i++) {
            pt[i] = ct[i] ^ k[i % 32];
        }
        emit CookieRead(msg.sender, CookieType.Persistent, name, string(pt), CookieDefenseType.Encryption);
    }
}
