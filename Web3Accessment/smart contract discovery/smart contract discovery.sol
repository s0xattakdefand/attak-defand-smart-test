// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SmartContractDiscoverySuite.sol
/// @notice On‐chain analogues of “Smart Contract Discovery” patterns:
///   Types: SourceCodeSearch, BytecodeAnalysis, Decompilation, ABIExtraction  
///   AttackTypes: Misinformation, Tampering, Replay, Noise  
///   DefenseTypes: AccessControl, Verification, RateLimit, SignatureValidation, AuditLogging

enum SmartContractDiscoveryType    { SourceCodeSearch, BytecodeAnalysis, Decompilation, ABIExtraction }
enum SCDAttackType                  { Misinformation, Tampering, Replay, Noise }
enum SCDDefenseType                 { AccessControl, Verification, RateLimit, SignatureValidation, AuditLogging }

error SCD__NotAuthorized();
error SCD__InvalidMetadata();
error SCD__TooManyRequests();
error SCD__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DISCOVERY REGISTRY
//    • ❌ no checks: anyone may register or read discovery → Misinformation
////////////////////////////////////////////////////////////////////////////////
contract SmartContractDiscoveryVuln {
    mapping(address => string[]) public discoveries;

    event ContractDiscovered(
        address indexed who,
        address indexed target,
        string            metadata,
        SmartContractDiscoveryType dtype,
        SCDAttackType     attack
    );
    event DiscoveryFetched(
        address indexed who,
        address indexed target,
        SmartContractDiscoveryType dtype,
        SCDAttackType     attack
    );

    function discoverContract(
        address target,
        string calldata metadata,
        SmartContractDiscoveryType dtype
    ) external {
        discoveries[target].push(metadata);
        emit ContractDiscovered(msg.sender, target, metadata, dtype, SCDAttackType.Misinformation);
    }

    function fetchDiscoveries(
        address target,
        SmartContractDiscoveryType dtype
    ) external view returns (string[] memory) {
        emit DiscoveryFetched(msg.sender, target, dtype, SCDAttackType.Noise);
        return discoveries[target];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates tampering, replay, noise, misinformation
////////////////////////////////////////////////////////////////////////////////
contract Attack_SmartContractDiscovery {
    SmartContractDiscoveryVuln public target;
    address public lastTarget;
    string  public lastMetadata;
    SmartContractDiscoveryType public lastType;

    constructor(SmartContractDiscoveryVuln _t) {
        target = _t;
    }

    function spoofDiscovery(address _target, string calldata meta) external {
        target.discoverContract(_target, meta, SmartContractDiscoveryType.SourceCodeSearch);
        lastTarget   = _target;
        lastMetadata = meta;
        lastType     = SmartContractDiscoveryType.SourceCodeSearch;
    }

    function tamperDiscovery(address _target, string calldata fake) external {
        target.discoverContract(_target, fake, SmartContractDiscoveryType.Decompilation);
    }

    function replayLast() external {
        target.discoverContract(lastTarget, lastMetadata, lastType);
    }

    function spam(address _target, string calldata meta, uint256 n) external {
        for(uint i=0;i<n;i++){
            target.discoverContract(_target, meta, SmartContractDiscoveryType.ABIExtraction);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may register discoveries
////////////////////////////////////////////////////////////////////////////////
contract SmartContractDiscoverySafeAccess {
    mapping(address => string[]) public discoveries;
    address public owner;

    event ContractDiscovered(
        address indexed who,
        address indexed target,
        string            metadata,
        SmartContractDiscoveryType dtype,
        SCDDefenseType    defense
    );
    event DiscoveryFetched(
        address indexed who,
        address indexed target,
        SmartContractDiscoveryType dtype,
        SCDDefenseType    defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert SCD__NotAuthorized();
        _;
    }

    function discoverContract(
        address target,
        string calldata metadata,
        SmartContractDiscoveryType dtype
    ) external onlyOwner {
        discoveries[target].push(metadata);
        emit ContractDiscovered(msg.sender, target, metadata, dtype, SCDDefenseType.AccessControl);
    }

    function fetchDiscoveries(
        address target,
        SmartContractDiscoveryType dtype
    ) external view returns (string[] memory) {
        emit DiscoveryFetched(msg.sender, target, dtype, SCDDefenseType.AccessControl);
        return discoveries[target];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VERIFICATION & RATE LIMIT
//    • ✅ Defense: Verification – metadata nonempty  
//               RateLimit     – cap registrations per block
////////////////////////////////////////////////////////////////////////////////
contract SmartContractDiscoverySafeValidate {
    mapping(address => string[]) public discoveries;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public regsInBlock;
    uint256 public constant MAX_REGS = 5;

    event ContractDiscovered(
        address indexed who,
        address indexed target,
        string            metadata,
        SmartContractDiscoveryType dtype,
        SCDDefenseType    defense
    );
    event DiscoveryFetched(
        address indexed who,
        address indexed target,
        SmartContractDiscoveryType dtype,
        SCDDefenseType    defense
    );

    error SCD__InvalidMetadata();
    error SCD__TooManyRequests();

    function discoverContract(
        address target,
        string calldata metadata,
        SmartContractDiscoveryType dtype
    ) external {
        if (bytes(metadata).length == 0) revert SCD__InvalidMetadata();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]  = block.number;
            regsInBlock[msg.sender] = 0;
        }
        regsInBlock[msg.sender]++;
        if (regsInBlock[msg.sender] > MAX_REGS) revert SCD__TooManyRequests();

        discoveries[target].push(metadata);
        emit ContractDiscovered(msg.sender, target, metadata, dtype, SCDDefenseType.Verification);
    }

    function fetchDiscoveries(
        address target,
        SmartContractDiscoveryType dtype
    ) external view returns (string[] memory) {
        emit DiscoveryFetched(msg.sender, target, dtype, SCDDefenseType.RateLimit);
        return discoveries[target];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin signature  
//               AuditLogging       – record every operation
////////////////////////////////////////////////////////////////////////////////
contract SmartContractDiscoverySafeAdvanced {
    mapping(address => string[]) public discoveries;
    address public signer;

    event ContractDiscovered(
        address indexed who,
        address indexed target,
        string            metadata,
        SmartContractDiscoveryType dtype,
        SCDDefenseType    defense
    );
    event DiscoveryFetched(
        address indexed who,
        address indexed target,
        SmartContractDiscoveryType dtype,
        SCDDefenseType    defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        address           target,
        SmartContractDiscoveryType dtype,
        SCDDefenseType    defense
    );

    error SCD__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function discoverContract(
        address target,
        string calldata metadata,
        SmartContractDiscoveryType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(target, metadata, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SCD__InvalidSignature();

        discoveries[target].push(metadata);
        emit ContractDiscovered(msg.sender, target, metadata, dtype, SCDDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "discoverContract", target, dtype, SCDDefenseType.AuditLogging);
    }

    function fetchDiscoveries(
        address target,
        SmartContractDiscoveryType dtype,
        bytes calldata sig
    ) external view returns (string[] memory) {
        bytes32 h = keccak256(abi.encodePacked("fetch", target, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SCD__InvalidSignature();

        emit DiscoveryFetched(msg.sender, target, dtype, SCDDefenseType.AuditLogging);
        return discoveries[target];
    }
}
