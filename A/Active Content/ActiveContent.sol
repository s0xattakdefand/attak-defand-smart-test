// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ActiveContentSuite.sol
/// @notice On-chain analogues of “Active Content” execution patterns:
///   Types: Scripts, Applets, WebAssembly, Plugins  
///   AttackTypes: CrossSiteScript, DriveByDownload, MaliciousScript, ExploitPayload  
///   DefenseTypes: ContentSecurityPolicy, Sanitization, Sandbox, Whitelisting

enum ActiveContentType           { Scripts, Applets, WebAssembly, Plugins }
enum ActiveContentAttackType     { CrossSiteScript, DriveByDownload, MaliciousScript, ExploitPayload }
enum ActiveContentDefenseType    { ContentSecurityPolicy, Sanitization, Sandbox, Whitelisting }

error AC__NotAllowed();
error AC__BadContent();
error AC__TooMany();
error AC__NotWhitelisted();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE EXECUTOR
//
//    • no restrictions: any content may run → CrossSiteScript
////////////////////////////////////////////////////////////////////////////////
contract ActiveContentVuln {
    mapping(uint256 => string) public registry;
    event ContentExecuted(
        address indexed who,
        uint256 indexed id,
        ActiveContentType  ctype,
        string             payload,
        ActiveContentAttackType attack
    );

    function register(uint256 id, ActiveContentType ctype, string calldata payload) external {
        registry[id] = payload;
    }

    function execute(uint256 id, ActiveContentType ctype) external {
        string memory payload = registry[id];
        // ❌ no checks: content executes directly
        emit ContentExecuted(msg.sender, id, ctype, payload, ActiveContentAttackType.CrossSiteScript);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • injects malicious script and triggers exploit payload
////////////////////////////////////////////////////////////////////////////////
contract Attack_ActiveContent {
    ActiveContentVuln public target;
    constructor(ActiveContentVuln _t) { target = _t; }

    function inject(uint256 id) external {
        // attacker registers a malicious script
        string memory evil = "<script>stealCookies()</script>";
        target.register(id, ActiveContentType.Scripts, evil);
        // then executes it
        target.execute(id, ActiveContentType.Scripts);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH CONTENT SECURITY POLICY
//
//    • Defense: only allow content from approved sources
////////////////////////////////////////////////////////////////////////////////
contract ActiveContentSafeCSP {
    mapping(address => bool) public allowedSources;
    mapping(uint256 => string) public registry;
    event ContentExecuted(
        address indexed who,
        uint256 indexed id,
        ActiveContentType  ctype,
        ActiveContentDefenseType defense
    );

    error AC__NotAllowed();

    constructor() {
        allowedSources[msg.sender] = true;
    }

    function setSourceAllowed(address src, bool ok) external {
        require(allowedSources[msg.sender], "only admin");
        allowedSources[src] = ok;
    }

    function register(uint256 id, string calldata payload) external {
        registry[id] = payload;
    }

    function execute(uint256 id, ActiveContentType ctype) external {
        if (!allowedSources[msg.sender]) revert AC__NotAllowed();
        // CSP enforcement stub
        emit ContentExecuted(msg.sender, id, ctype, ActiveContentDefenseType.ContentSecurityPolicy);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH SANITIZATION
//
//    • Defense: strip dangerous tags before execution
////////////////////////////////////////////////////////////////////////////////
contract ActiveContentSafeSanitize {
    mapping(uint256 => string) public registry;
    event ContentExecuted(
        address indexed who,
        uint256 indexed id,
        ActiveContentType  ctype,
        string             sanitized,
        ActiveContentDefenseType defense
    );

    error AC__BadContent();

    function register(uint256 id, string calldata payload) external {
        registry[id] = payload;
    }

    function execute(uint256 id, ActiveContentType ctype) external {
        string memory payload = registry[id];
        bytes memory b = bytes(payload);
        bytes memory out = new bytes(b.length);
        uint outIdx;
        // simple sanitization: remove '<' and '>' characters
        for (uint i = 0; i < b.length; i++) {
            if (b[i] == "<" || b[i] == ">") continue;
            out[outIdx++] = b[i];
        }
        string memory sanitized = string(slice(out, 0, outIdx));
        emit ContentExecuted(msg.sender, id, ctype, sanitized, ActiveContentDefenseType.Sanitization);
    }

    // helper to slice byte array
    function slice(bytes memory data, uint start, uint len) internal pure returns (bytes memory) {
        bytes memory ret = new bytes(len);
        for (uint i = 0; i < len; i++) {
            ret[i] = data[start + i];
        }
        return ret;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE WITH SANDBOX + WHITELISTING
//
//    • Defense: execute only whitelisted content IDs in isolated sandbox
////////////////////////////////////////////////////////////////////////////////
contract ActiveContentSafeSandbox {
    mapping(uint256 => string) public registry;
    mapping(uint256 => bool)    public whitelisted;
    event ContentExecuted(
        address indexed who,
        uint256 indexed id,
        ActiveContentType  ctype,
        ActiveContentDefenseType defense
    );

    error AC__NotWhitelisted();

    function register(uint256 id, string calldata payload) external {
        registry[id] = payload;
    }

    function whitelistContent(uint256 id, bool ok) external {
        // in practice restricted to admin
        whitelisted[id] = ok;
    }

    function execute(uint256 id, ActiveContentType ctype) external {
        if (!whitelisted[id]) revert AC__NotWhitelisted();
        // sandbox stub: content runs in isolation
        emit ContentExecuted(msg.sender, id, ctype, ActiveContentDefenseType.Sandbox);
    }
}
