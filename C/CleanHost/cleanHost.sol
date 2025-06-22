// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CleanHostSuite.sol
/// @notice On‐chain analogues of “Clean Host” assurance patterns:
///   Types: BootScan, OnDemand, Scheduled, LiveMonitor  
///   AttackTypes: MalwareInjection, RootkitInstall, ConfigTampering, DenialOfService  
///   DefenseTypes: AccessControl, AntivirusScan, IntegrityCheck, Isolation, RateLimit

enum CleanHostType           { BootScan, OnDemand, Scheduled, LiveMonitor }
enum CleanHostAttackType     { MalwareInjection, RootkitInstall, ConfigTampering, DenialOfService }
enum CleanHostDefenseType    { AccessControl, AntivirusScan, IntegrityCheck, Isolation, RateLimit }

error CH__Unauthorized();
error CH__ScanFailed();
error CH__TooManyRequests();
error CH__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CLEAN HOST MANAGER
//    • ❌ no checks: anyone may mark host clean → MalwareInjection
////////////////////////////////////////////////////////////////////////////////
contract CleanHostVuln {
    mapping(uint256 => bool) public isClean;

    event HostCleaned(
        address indexed who,
        uint256           hostId,
        CleanHostType     ctype,
        CleanHostAttackType attack
    );

    function cleanHost(uint256 hostId, CleanHostType ctype) external {
        isClean[hostId] = true;
        emit HostCleaned(msg.sender, hostId, ctype, CleanHostAttackType.MalwareInjection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates malware injection, rootkit install, tampering, DoS
////////////////////////////////////////////////////////////////////////////////
contract Attack_CleanHost {
    CleanHostVuln public target;
    uint256 public lastHost;
    CleanHostType public lastType;

    constructor(CleanHostVuln _t) {
        target = _t;
    }

    function injectMalware(uint256 hostId) external {
        target.cleanHost(hostId, CleanHostType.BootScan);
        lastHost = hostId;
        lastType = CleanHostType.BootScan;
    }

    function installRootkit(uint256 hostId) external {
        target.cleanHost(hostId, CleanHostType.OnDemand);
    }

    function tamperConfig(uint256 hostId) external {
        target.cleanHost(hostId, CleanHostType.Scheduled);
    }

    function denialOfService(uint256 hostId) external {
        // spam clean calls
        for (uint i = 0; i < 3; i++) {
            target.cleanHost(hostId, CleanHostType.LiveMonitor);
        }
    }

    function replay() external {
        target.cleanHost(lastHost, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may mark clean
////////////////////////////////////////////////////////////////////////////////
contract CleanHostSafeAccess {
    mapping(uint256 => bool) public isClean;
    address public owner;

    event HostCleaned(
        address indexed who,
        uint256           hostId,
        CleanHostType     ctype,
        CleanHostDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function cleanHost(uint256 hostId, CleanHostType ctype) external {
        if (msg.sender != owner) revert CH__Unauthorized();
        isClean[hostId] = true;
        emit HostCleaned(msg.sender, hostId, ctype, CleanHostDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ANTIVIRUS SCAN
//    • ✅ Defense: AntivirusScan – require prior scan pass
////////////////////////////////////////////////////////////////////////////////
contract CleanHostSafeScan {
    mapping(uint256 => bool) public isScanned;
    mapping(uint256 => bool) public isClean;

    event HostScanned(
        address indexed who,
        uint256           hostId,
        CleanHostDefenseType defense
    );
    event HostCleaned(
        address indexed who,
        uint256           hostId,
        CleanHostType     ctype,
        CleanHostDefenseType defense
    );

    error CH__ScanFailed();

    function runScan(uint256 hostId) external {
        // stub: always pass
        isScanned[hostId] = true;
        emit HostScanned(msg.sender, hostId, CleanHostDefenseType.AntivirusScan);
    }

    function cleanHost(uint256 hostId, CleanHostType ctype) external {
        if (!isScanned[hostId]) revert CH__ScanFailed();
        isClean[hostId] = true;
        emit HostCleaned(msg.sender, hostId, ctype, CleanHostDefenseType.AntivirusScan);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & RATE LIMIT
//    • ✅ Defense: SignatureValidation – require admin signature  
//               RateLimit           – cap cleans per block
////////////////////////////////////////////////////////////////////////////////
contract CleanHostSafeAdvanced {
    mapping(uint256 => bool) public isClean;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    address public signer;
    uint256 public constant MAX_CALLS = 3;

    event HostCleaned(
        address indexed who,
        uint256           hostId,
        CleanHostType     ctype,
        CleanHostDefenseType defense
    );

    constructor(address _signer) {
        signer = _signer;
    }

    function cleanHost(
        uint256 hostId,
        CleanHostType ctype,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CH__TooManyRequests();

        // verify signature over (hostId||ctype)
        bytes32 h = keccak256(abi.encodePacked(hostId, ctype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CH__InvalidSignature();

        isClean[hostId] = true;
        emit HostCleaned(msg.sender, hostId, ctype, CleanHostDefenseType.RateLimit);
    }
}
