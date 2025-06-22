// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DomainNameSuite.sol
/// @notice On‑chain analogues of “Domain Name” management patterns:
///   Types: FQDN, SLD, TLD, Wildcard  
///   AttackTypes: Typosquatting, HomographAttack, DNSCachePoisoning, NXDOMAINFlood  
///   DefenseTypes: DNSSECValidation, BlacklistFilter, HomographDetection, RateLimit  

enum DomainNameType          { FQDN, SLD, TLD, Wildcard }
enum DomainNameAttackType    { Typosquatting, HomographAttack, DNSCachePoisoning, NXDOMAINFlood }
enum DomainNameDefenseType   { DNSSECValidation, BlacklistFilter, HomographDetection, RateLimit }

error DN__InvalidSignature();
error DN__Blacklisted();
error DN__SuspiciousName();
error DN__TooMany();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE REGISTRY
//
//    • anyone may register or resolve any name → Typosquatting, NXDOMAINFlood
////////////////////////////////////////////////////////////////////////////////
contract DomainNameVuln {
    mapping(string => address) public ownerOf;
    event DomainRegistered(
        address indexed by,
        string            name,
        DomainNameType    dtype,
        DomainNameAttackType attack
    );
    event DomainResolved(
        address indexed by,
        string            name,
        address           resolvedTo,
        DomainNameAttackType attack
    );

    function register(string calldata name, DomainNameType dtype) external {
        ownerOf[name] = msg.sender;
        emit DomainRegistered(msg.sender, name, dtype, DomainNameAttackType.Typosquatting);
    }

    function resolve(string calldata name) external view returns (address) {
        emit DomainResolved(msg.sender, name, ownerOf[name], DomainNameAttackType.NXDOMAINFlood);
        return ownerOf[name];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • floods registrations (NXDOMAINFlood) and registers look‑alikes (Typosquatting)
////////////////////////////////////////////////////////////////////////////////
contract Attack_DomainName {
    DomainNameVuln public target;
    constructor(DomainNameVuln _t) { target = _t; }

    function floodRegister(string[] calldata names, DomainNameType dtype) external {
        for (uint i; i < names.length; i++) {
            target.register(names[i], dtype);
        }
    }

    function typoSquat(string calldata legit, string calldata lookalike, DomainNameType dtype) external {
        target.register(lookalike, dtype);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE REGISTRY WITH DNSSEC & BLACKLIST FILTER
//
//    • Defense: DNSSECValidation – require oracle signature on registration  
//               BlacklistFilter – block known bad names on resolve
////////////////////////////////////////////////////////////////////////////////
contract DomainNameSafe {
    mapping(string => address) public ownerOf;
    mapping(string => bool)    public blacklist;
    address public dnssecOracle;
    event DomainRegistered(
        address indexed by,
        string            name,
        DomainNameType    dtype,
        DomainNameDefenseType defense
    );
    event DomainResolved(
        address indexed by,
        string            name,
        address           resolvedTo,
        DomainNameDefenseType defense
    );

    constructor(address oracle) {
        dnssecOracle = oracle;
    }

    /// only accept registration with oracle signature over (name, owner)
    function register(
        string calldata name,
        DomainNameType dtype,
        bytes calldata  oracleSig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(name, msg.sender));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(oracleSig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != dnssecOracle) revert DN__InvalidSignature();
        ownerOf[name] = msg.sender;
        emit DomainRegistered(msg.sender, name, dtype, DomainNameDefenseType.DNSSECValidation);
    }

    /// resolve only non‑blacklisted names
    function resolve(string calldata name) external view returns (address) {
        if (blacklist[name]) revert DN__Blacklisted();
        emit DomainResolved(msg.sender, name, ownerOf[name], DomainNameDefenseType.BlacklistFilter);
        return ownerOf[name];
    }

    /// owner can manage blacklist
    function setBlacklist(string calldata name, bool blocked) external {
        // assume dnssecOracle is owner for simplicity
        require(msg.sender == dnssecOracle, "only oracle");
        blacklist[name] = blocked;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) ADVANCED SAFE WITH HOMOGRAPH DETECTION & RATE‑LIMIT
//
//    • Defense: HomographDetection – reject names with mixed scripts  
//               RateLimit – cap registrations per block
////////////////////////////////////////////////////////////////////////////////
contract DomainNameSafeAdvanced {
    mapping(string => address) public ownerOf;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_REG_PER_BLOCK = 3;

    event DomainRegistered(
        address indexed by,
        string            name,
        DomainNameType    dtype,
        DomainNameDefenseType defense
    );

    error DN__SuspiciousName();
    error DN__TooMany();

    /// register with homograph check and rate‑limit
    function register(string calldata name, DomainNameType dtype) external {
        // rate‑limit per addr
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_REG_PER_BLOCK) revert DN__TooMany();

        // simple homograph detection: reject if contains both Latin and Cyrillic 'a' (U+0061, U+0430)
        bytes memory b = bytes(name);
        bool hasLatinA;
        bool hasCyrilA;
        for (uint i; i < b.length; i++) {
            if (b[i] == 0x61) hasLatinA = true;
            if (b[i] == 0xD0 && i + 1 < b.length && b[i+1] == 0xB0) hasCyrilA = true;
        }
        if (hasLatinA && hasCyrilA) revert DN__SuspiciousName();

        ownerOf[name] = msg.sender;
        emit DomainRegistered(msg.sender, name, dtype, DomainNameDefenseType.HomographDetection);
    }
}
