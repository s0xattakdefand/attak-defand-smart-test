// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UniformResourceIdentifierSuite.sol
/// @notice On‑chain analogues of “Uniform Resource Identifier” (URI) handling patterns:
///   Types: URL, URN, DataURI  
///   AttackTypes: SSRF, OpenRedirect, Injection  
///   DefenseTypes: ValidateScheme, WhitelistURI, EncodeParams  

enum URIType            { URL, URN, DataURI }
enum URIAttackType      { SSRF, OpenRedirect, Injection }
enum URIDefenseType     { ValidateScheme, WhitelistURI, EncodeParams }

error URI__BadScheme();
error URI__NotAllowed();
error URI__BadInput();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE URI FETCHER (no validation, default allow)
///    • Type: URL  
///    • Attack: SSRF (server‑side request forgery)  
///─────────────────────────────────────────────────────────────────────────────
contract URIFetchVuln {
    event Fetched(address indexed who, string uri, URIAttackType attack);

    /// ❌ no checks on URI → any endpoint may be invoked
    function fetch(string calldata uri) external {
        // off‑chain SSRF attacker reads internal resources
        emit Fetched(msg.sender, uri, URIAttackType.SSRF);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///    • Demonstrates SSRF by fetching localhost/admin  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_URIFetch {
    URIFetchVuln public target;
    constructor(URIFetchVuln _t) { target = _t; }

    function exploit() external {
        target.fetch("http://127.0.0.1/admin");
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE SCHEME VALIDATION
///    • Defense: ValidateScheme – only allow HTTPS URLs  
///─────────────────────────────────────────────────────────────────────────────
contract URIFetchSafeScheme {
    event Fetched(address indexed who, string uri, URIDefenseType defense);

    /// ✅ require URI to start with "https://"
    function fetch(string calldata uri) external {
        bytes memory u = bytes(uri);
        bytes memory https = bytes("https://");
        require(u.length >= https.length, "URI too short");
        for (uint i = 0; i < https.length; i++) {
            if (u[i] != https[i]) revert URI__BadScheme();
        }
        emit Fetched(msg.sender, uri, URIDefenseType.ValidateScheme);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE WHITELISTED URIS
///    • Defense: WhitelistURI – only pre‑approved URIs  
///─────────────────────────────────────────────────────────────────────────────
contract URIFetchSafeWhitelist {
    mapping(string => bool) public allowed;
    address public owner;
    event Fetched(address indexed who, string uri, URIDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// only owner may approve or revoke URIs
    function setAllowed(string calldata uri, bool ok) external {
        require(msg.sender == owner, "not owner");
        allowed[uri] = ok;
    }

    /// ✅ only allow fetch if URI is whitelisted
    function fetch(string calldata uri) external {
        if (!allowed[uri]) revert URI__NotAllowed();
        emit Fetched(msg.sender, uri, URIDefenseType.WhitelistURI);
    }
}
