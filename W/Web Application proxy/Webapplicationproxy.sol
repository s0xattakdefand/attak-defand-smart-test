// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebApplicationProxySuite.sol
/// @notice On‐chain analogues of “Web Application Proxy” patterns:
///   Types: Reverse, Transparent, API, WAF  
///   AttackTypes: Tampering, Injection, PathTraversal, SSLStrip  
///   DefenseTypes: Authentication, InputValidation, RateLimit, TLSValidation  

enum WebApplicationProxyType       { Reverse, Transparent, API, WAF }
enum WebApplicationProxyAttackType { Tampering, Injection, PathTraversal, SSLStrip }
enum WebApplicationProxyDefenseType{ Authentication, InputValidation, RateLimit, TLSValidation }

error WAPX__NotAllowed();
error WAPX__InvalidInput();
error WAPX__TooManyRequests();
error WAPX__InvalidTLS();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PROXY
//    • ❌ no checks: forwards any request → Tampering
////////////////////////////////////////////////////////////////////////////////
contract WAPXVuln {
    event RequestProxied(
        address indexed client,
        address           backend,
        bytes             data,
        WebApplicationProxyType       ptype,
        WebApplicationProxyAttackType attack
    );

    function proxyRequest(address backend, bytes calldata data, WebApplicationProxyType ptype) external {
        // naive forward
        (bool ok,) = backend.call(data);
        require(ok);
        emit RequestProxied(msg.sender, backend, data, ptype, WebApplicationProxyAttackType.Tampering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates header injection and path traversal
////////////////////////////////////////////////////////////////////////////////
contract Attack_WAPX {
    WAPXVuln public target;
    bytes public lastData;
    address public lastBackend;

    constructor(WAPXVuln _t) { target = _t; }

    function inject(address backend, bytes calldata data) external {
        // attacker injects malicious payload
        target.proxyRequest(backend, data, WebApplicationProxyType.Transparent);
        lastBackend = backend;
        lastData = data;
    }

    function replay() external {
        // replay captured request
        target.proxyRequest(lastBackend, lastData, WebApplicationProxyType.Transparent);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE PROXY WITH AUTHENTICATION
//    • ✅ Defense: Authentication – only allowed clients
////////////////////////////////////////////////////////////////////////////////
contract WAPXSafeAuth {
    mapping(address => bool) public allowed;
    event RequestProxied(
        address indexed client,
        address           backend,
        WebApplicationProxyType       ptype,
        WebApplicationProxyDefenseType defense
    );

    constructor() {
        allowed[msg.sender] = true;
    }

    function setAllowed(address client, bool ok) external {
        require(allowed[msg.sender], "admin only");
        allowed[client] = ok;
    }

    function proxyRequest(address backend, bytes calldata /*data*/, WebApplicationProxyType ptype) external {
        if (!allowed[msg.sender]) revert WAPX__NotAllowed();
        // forward stub
        emit RequestProxied(msg.sender, backend, ptype, WebApplicationProxyDefenseType.Authentication);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE PROXY WITH INPUT VALIDATION & RATE-LIMIT
//    • ✅ Defense: InputValidation – sanitize path  
//               RateLimit – cap per block
////////////////////////////////////////////////////////////////////////////////
contract WAPXSafeValidateRate {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;
    event RequestProxied(
        address indexed client,
        address           backend,
        string            path,
        WebApplicationProxyType       ptype,
        WebApplicationProxyDefenseType defense
    );
    error WAPX__InvalidInput();
    error WAPX__TooManyRequests();

    function _sanitize(string memory path) internal pure returns (string memory) {
        bytes memory b = bytes(path);
        for (uint i; i < b.length; i++) {
            // reject "../" segments
            if (i+2 < b.length && b[i]=='.' && b[i+1]=='.' && b[i+2]=='/') revert WAPX__InvalidInput();
        }
        return path;
    }

    function proxyRequest(address backend, string calldata path, WebApplicationProxyType ptype) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WAPX__TooManyRequests();

        string memory clean = _sanitize(path);
        // forward stub
        emit RequestProxied(msg.sender, backend, clean, ptype, WebApplicationProxyDefenseType.InputValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH TLS VALIDATION
//    • ✅ Defense: TLSValidation – verify backend certificate signature
////////////////////////////////////////////////////////////////////////////////
contract WAPXSafeTLS {
    address public ca;
    mapping(bytes32 => bool) public seenCert;
    event RequestProxied(
        address indexed client,
        address           backend,
        bytes             data,
        WebApplicationProxyType       ptype,
        WebApplicationProxyDefenseType defense
    );
    error WAPX__InvalidTLS();

    constructor(address _ca) {
        ca = _ca;
    }

    function proxyRequest(
        address backend,
        bytes calldata data,
        WebApplicationProxyType ptype,
        bytes calldata certSig   // signature over (backend||data)
    ) external {
        // verify signature
        bytes32 msgHash = keccak256(abi.encodePacked(backend, data));
        if (seenCert[msgHash]) revert WAPX__InvalidTLS();
        seenCert[msgHash] = true;
        bytes32 ethMsg = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(certSig, (uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != ca) revert WAPX__InvalidTLS();

        // forward stub
        emit RequestProxied(msg.sender, backend, data, ptype, WebApplicationProxyDefenseType.TLSValidation);
    }
}
