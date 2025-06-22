// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ReconnaissanceAndAttackSurfaceMappingSuite.sol
/// @notice On‐chain analogues of “Reconnaissance and Attack Surface Mapping” patterns:
///   Types: Passive, Active, Technical, Social  
///   AttackTypes: PortScan, OSFingerprinting, SocialEngineering, NetworkMapping  
///   DefenseTypes: AccessControl, RateLimit, Logging, SignatureValidation, AuditLogging

enum ReconType               { Passive, Active, Technical, Social }
enum ReconAttackType         { PortScan, OSFingerprinting, SocialEngineering, NetworkMapping }
enum ReconDefenseType        { AccessControl, RateLimit, Logging, SignatureValidation, AuditLogging }

error RASM__NotAuthorized();
error RASM__TooManyRequests();
error RASM__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE MAPPING
//    • ❌ no checks: anyone may map any target’s surfaces → NetworkMapping
////////////////////////////////////////////////////////////////////////////////
contract ReconMappingVuln {
    mapping(address => string[]) public surfaces;  // target → discovered surfaces

    event SurfaceMapped(
        address indexed who,
        address indexed target,
        string            surface,
        ReconType         rtype,
        ReconAttackType   attack
    );

    function mapSurface(
        address target,
        string calldata surface,
        ReconType rtype
    ) external {
        surfaces[target].push(surface);
        emit SurfaceMapped(msg.sender, target, surface, rtype, ReconAttackType.NetworkMapping);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates port scan, OS fingerprinting, social‐engineering recon
////////////////////////////////////////////////////////////////////////////////
contract Attack_ReconMapping {
    ReconMappingVuln public target;
    address public lastTarget;
    string  public lastSurface;
    ReconType public lastType;

    constructor(ReconMappingVuln _t) {
        target = _t;
    }

    function portScan(address targetAddr) external {
        string memory svc = "open:80,443";
        target.mapSurface(targetAddr, svc, ReconType.Active);
        lastTarget  = targetAddr;
        lastSurface = svc;
        lastType    = ReconType.Active;
    }

    function osFingerprint(address targetAddr) external {
        string memory os = "Linux Kernel 5.x";
        target.mapSurface(targetAddr, os, ReconType.Technical);
    }

    function socialEngine(address targetAddr) external {
        string memory info = "linkedInProfile";
        target.mapSurface(targetAddr, info, ReconType.Social);
    }

    function replay() external {
        target.mapSurface(lastTarget, lastSurface, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may map
////////////////////////////////////////////////////////////////////////////////
contract ReconMappingSafeAccess {
    mapping(address => string[]) public surfaces;
    address public owner;

    event SurfaceMapped(
        address indexed who,
        address indexed target,
        string            surface,
        ReconType         rtype,
        ReconDefenseType  defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert RASM__NotAuthorized();
        _;
    }

    function mapSurface(
        address target,
        string calldata surface,
        ReconType rtype
    ) external onlyOwner {
        surfaces[target].push(surface);
        emit SurfaceMapped(msg.sender, target, surface, rtype, ReconDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RATE LIMIT & LOGGING
//    • ✅ Defense: RateLimit – cap maps per block  
//               Logging   – record every map
////////////////////////////////////////////////////////////////////////////////
contract ReconMappingSafeRateLimit {
    mapping(address => string[]) public surfaces;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event SurfaceMapped(
        address indexed who,
        address indexed target,
        string            surface,
        ReconType         rtype,
        ReconDefenseType  defense
    );

    error RASM__TooManyRequests();

    function mapSurface(
        address target,
        string calldata surface,
        ReconType rtype
    ) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert RASM__TooManyRequests();

        surfaces[target].push(surface);
        emit SurfaceMapped(msg.sender, target, surface, rtype, ReconDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed params  
//               AuditLogging      – record each mapping
////////////////////////////////////////////////////////////////////////////////
contract ReconMappingSafeAdvanced {
    mapping(address => string[]) public surfaces;
    address public signer;

    event SurfaceMapped(
        address indexed who,
        address indexed target,
        string            surface,
        ReconType         rtype,
        ReconDefenseType  defense
    );
    event AuditLog(
        address indexed who,
        address indexed target,
        string            surface,
        ReconType         rtype,
        ReconDefenseType  defense
    );

    error RASM__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function mapSurface(
        address target,
        string calldata surface,
        ReconType rtype,
        bytes calldata sig
    ) external {
        // verify signature over (target||surface||rtype)
        bytes32 h = keccak256(abi.encodePacked(target, surface, rtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert RASM__InvalidSignature();

        surfaces[target].push(surface);
        emit SurfaceMapped(msg.sender, target, surface, rtype, ReconDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, target, surface, rtype, ReconDefenseType.AuditLogging);
    }
}
