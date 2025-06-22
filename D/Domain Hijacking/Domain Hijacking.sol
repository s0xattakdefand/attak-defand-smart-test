// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DomainHijackSuite.sol
/// @notice On‑chain analogues of “Domain Hijack” patterns:
///   Types: TransientHijack, SubdomainHijack, RegistrarHijack  
///   AttackTypes: RegistrarCompromise, CachePoisoning, RedirectHijack  
///   DefenseTypes: DNSSECValidation, RegistrarLock, MonitoringAlert  

enum DomainHijackType          { TransientHijack, SubdomainHijack, RegistrarHijack }
enum DomainHijackAttackType    { RegistrarCompromise, CachePoisoning, RedirectHijack }
enum DomainHijackDefenseType   { DNSSECValidation, RegistrarLock, MonitoringAlert }

error DHJ__NotAuthorized();
error DHJ__InvalidSignature();
error DHJ__Locked();
error DHJ__TooManyAlerts();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE REGISTRY
//
//    • anyone may register or transfer any domain → RegistrarCompromise
////////////////////////////////////////////////////////////////////////////////
contract DomainHijackVuln {
    mapping(string => address) public ownerOf;
    event DomainChanged(
        address indexed by,
        string           domain,
        address          newOwner,
        DomainHijackAttackType attack
    );

    /// ❌ no checks: anyone can set or override owner
    function setOwner(string calldata domain, address newOwner) external {
        ownerOf[domain] = newOwner;
        emit DomainChanged(msg.sender, domain, newOwner, DomainHijackAttackType.RegistrarCompromise);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates takeover and cache poisoning redirect
////////////////////////////////////////////////////////////////////////////////
contract Attack_DomainHijack {
    DomainHijackVuln public target;
    constructor(DomainHijackVuln _t) { target = _t; }

    /// hijack domain by calling setOwner
    function hijack(string calldata domain) external {
        target.setOwner(domain, msg.sender);
    }

    /// simulate cache poisoning by rapid flips
    function poisonCache(string calldata domain, address[] calldata maliciousOwners) external {
        for (uint i = 0; i < maliciousOwners.length; i++) {
            target.setOwner(domain, maliciousOwners[i]);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE DNSSEC‐ENABLED REGISTRY
//
//    • Defense: DNSSECValidation – require signed proof of ownership
////////////////////////////////////////////////////////////////////////////////
contract DomainHijackSafeDNSSEC {
    mapping(string => address) public ownerOf;
    address public dnssecOracle;
    event DomainChanged(
        address indexed by,
        string           domain,
        address          newOwner,
        DomainHijackDefenseType defense
    );

    constructor(address oracle) {
        dnssecOracle = oracle;
    }

    /// only accept updates with oracle signature over (domain,newOwner)
    function setOwner(
        string calldata domain,
        address newOwner,
        bytes calldata oracleSig
    ) external {
        // stub: validate signature by ecrecover of DNSSEC oracle
        bytes32 msgHash = keccak256(abi.encodePacked(domain, newOwner));
        bytes32 ethMsg = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(oracleSig, (uint8, bytes32, bytes32));
        address signer = ecrecover(ethMsg, v, r, s);
        if (signer != dnssecOracle) revert DHJ__InvalidSignature();

        ownerOf[domain] = newOwner;
        emit DomainChanged(msg.sender, domain, newOwner, DomainHijackDefenseType.DNSSECValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) ADVANCED SAFE WITH REGISTRAR LOCK & MONITORING
//
//    • Defense: RegistrarLock – prevent changes when locked  
//               MonitoringAlert – emit alerts on rapid change attempts
////////////////////////////////////////////////////////////////////////////////
contract DomainHijackSafeAdvanced {
    mapping(string => address) public ownerOf;
    mapping(string => bool)    public locked;
    mapping(string => uint256) public lastChangeBlock;
    mapping(string => uint256) public alertCount;
    uint256 public constant MAX_ALERTS = 3;

    address public registrar;
    event DomainChanged(
        address indexed by,
        string           domain,
        address          newOwner,
        DomainHijackDefenseType defense
    );
    event HijackAlert(
        address indexed by,
        string           domain,
        string           reason,
        DomainHijackDefenseType defense
    );

    error DHJ__Locked();
    error DHJ__TooManyAlerts();
    error DHJ__NotRegistrar();

    constructor(address _registrar) {
        registrar = _registrar;
    }

    modifier onlyRegistrar() {
        if (msg.sender != registrar) revert DHJ__NotRegistrar();
        _;
    }

    /// registrar may lock domains against transfer
    function setLock(string calldata domain, bool isLocked) external onlyRegistrar {
        locked[domain] = isLocked;
    }

    /// registrar may transfer ownership when unlocked
    function setOwner(string calldata domain, address newOwner) external onlyRegistrar {
        if (locked[domain]) revert DHJ__Locked();

        // monitoring: if changes too frequently, emit alert
        if (block.number == lastChangeBlock[domain]) {
            alertCount[domain]++;
            emit HijackAlert(msg.sender, domain, "rapid change", DomainHijackDefenseType.MonitoringAlert);
            if (alertCount[domain] > MAX_ALERTS) revert DHJ__TooManyAlerts();
        } else {
            alertCount[domain] = 0;
        }

        lastChangeBlock[domain] = block.number;
        ownerOf[domain] = newOwner;
        emit DomainChanged(msg.sender, domain, newOwner, DomainHijackDefenseType.RegistrarLock);
    }
}
