// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataCenterSecurityServerAdvancedSuite.sol
/// @notice On‐chain analogues for “Data Center Security Server Advanced” patterns:
///   Types: PhysicalSecurity, NetworkSecurity, ApplicationSecurity, Monitoring, DisasterRecovery  
///   AttackTypes: UnauthorizedAccess, DenialOfService, Misconfiguration, FirmwareTamper  
///   DefenseTypes: AccessControl, NetworkSegmentation, PatchManagement, Monitoring, SignatureValidation

enum DCSSAType             { PhysicalSecurity, NetworkSecurity, ApplicationSecurity, Monitoring, DisasterRecovery }
enum DCSSAAttackType       { UnauthorizedAccess, DenialOfService, Misconfiguration, FirmwareTamper }
enum DCSSADefenseType      { AccessControl, NetworkSegmentation, PatchManagement, Monitoring, SignatureValidation }

error DCSSA__NotAuthorized();
error DCSSA__TooManyRequests();
error DCSSA__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SERVER MANAGER
//    • ❌ no checks: anyone may configure or query server → UnauthorizedAccess, Misconfiguration
////////////////////////////////////////////////////////////////////////////////
contract DCSSA_Vuln {
    struct ServerConfig { bool firewalled; string firmware; }
    mapping(uint256 => ServerConfig) public configs;

    event Configured(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSAAttackType   attack
    );
    event Queried(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSAAttackType   attack
    );

    function configureServer(uint256 serverId, bool fw, string calldata firmware, DCSSAType dtype) external {
        configs[serverId] = ServerConfig(fw, firmware);
        emit Configured(msg.sender, serverId, dtype, DCSSAAttackType.Misconfiguration);
    }

    function queryServer(uint256 serverId, DCSSAType dtype) external view returns (bool, string memory) {
        emit Queried(msg.sender, serverId, dtype, DCSSAAttackType.UnauthorizedAccess);
        ServerConfig storage c = configs[serverId];
        return (c.firewalled, c.firmware);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized access, DoS, misconfig, firmware tamper
////////////////////////////////////////////////////////////////////////////////
contract DCSSA_Attack {
    DCSSA_Vuln public target;
    uint256 public lastId;

    constructor(DCSSA_Vuln _t) { target = _t; }

    function spoofConfigure(uint256 id) external {
        target.configureServer(id, false, "v0.0-compromised", DCSSAType.ApplicationSecurity);
        lastId = id;
    }

    function tamperFirmware(uint256 id) external {
        target.configureServer(id, true, "v0.0-firmware-tamp", DCSSAType.PhysicalSecurity);
    }

    function unauthorizedQuery(uint256 id) external {
        target.queryServer(id, DCSSAType.Monitoring);
    }

    function replayConfigure() external {
        target.configureServer(lastId, true, "v1.0", DCSSAType.DisasterRecovery);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may configure or query
////////////////////////////////////////////////////////////////////////////////
contract DCSSA_SafeAccess {
    struct ServerConfig { bool firewalled; string firmware; }
    mapping(uint256 => ServerConfig) public configs;
    address public owner;

    event Configured(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSADefenseType  defense
    );
    event Queried(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSADefenseType  defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DCSSA__NotAuthorized();
        _;
    }

    function configureServer(uint256 serverId, bool fw, string calldata firmware, DCSSAType dtype) external onlyOwner {
        configs[serverId] = ServerConfig(fw, firmware);
        emit Configured(msg.sender, serverId, dtype, DCSSADefenseType.AccessControl);
    }

    function queryServer(uint256 serverId, DCSSAType dtype) external view onlyOwner returns (bool, string memory) {
        emit Queried(msg.sender, serverId, dtype, DCSSADefenseType.AccessControl);
        ServerConfig storage c = configs[serverId];
        return (c.firewalled, c.firmware);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH NETWORK SEGMENTATION & RATE LIMIT
//    • ✅ Defense: NetworkSegmentation – require segment tag  
//               RateLimit           – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DCSSA_SafeSegRate {
    struct ServerConfig { bool firewalled; string firmware; }
    mapping(uint256 => ServerConfig) public configs;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 4;

    event Configured(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSADefenseType  defense
    );
    event Queried(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSADefenseType  defense
    );

    error DCSSA__TooManyRequests();
    error DCSSA__InvalidInput();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]  = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DCSSA__TooManyRequests();
        _;
    }

    function configureServer(
        uint256 serverId,
        bool fw,
        string calldata firmware,
        bytes32 segmentTag,
        DCSSAType dtype
    ) external rateLimit {
        if (segmentTag == bytes32(0)) revert DCSSA__InvalidInput();
        configs[serverId] = ServerConfig(fw, firmware);
        emit Configured(msg.sender, serverId, dtype, DCSSADefenseType.NetworkSegmentation);
    }

    function queryServer(uint256 serverId, bytes32 segmentTag, DCSSAType dtype)
        external
        rateLimit
        returns (bool, string memory)
    {
        if (segmentTag == bytes32(0)) revert DCSSA__InvalidInput();
        ServerConfig storage c = configs[serverId];
        emit Queried(msg.sender, serverId, dtype, DCSSADefenseType.RateLimit);
        return (c.firewalled, c.firmware);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & MONITORING
//    • ✅ Defense: SignatureValidation – require admin‐signed op  
//               Monitoring         – emit detailed logs
////////////////////////////////////////////////////////////////////////////////
contract DCSSA_SafeAdvanced {
    struct ServerConfig { bool firewalled; string firmware; }
    mapping(uint256 => ServerConfig) public configs;
    address public signer;

    event Configured(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSADefenseType  defense
    );
    event Queried(
        address indexed who,
        uint256           serverId,
        DCSSAType         dtype,
        DCSSADefenseType  defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           serverId,
        DCSSADefenseType  defense
    );

    error DCSSA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function configureServer(
        uint256 serverId,
        bool fw,
        string calldata firmware,
        DCSSAType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (who||serverId||fw||firmware||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, serverId, fw, firmware, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DCSSA__InvalidSignature();

        configs[serverId] = ServerConfig(fw, firmware);
        emit Configured(msg.sender, serverId, dtype, DCSSADefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "configureServer", serverId, DCSSADefenseType.AuditLogging);
    }

    function queryServer(
        uint256 serverId,
        DCSSAType dtype,
        bytes calldata sig
    ) external returns (bool, string memory) {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, serverId, dtype, "query"));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DCSSA__InvalidSignature();

        ServerConfig storage c = configs[serverId];
        emit Queried(msg.sender, serverId, dtype, DCSSADefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "queryServer", serverId, DCSSADefenseType.AuditLogging);
        return (c.firewalled, c.firmware);
    }
}
