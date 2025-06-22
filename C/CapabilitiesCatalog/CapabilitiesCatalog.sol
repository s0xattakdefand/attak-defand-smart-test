// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CapabilitiesCatalogSuite.sol
/// @notice On‐chain analogues of “Capabilities Catalog” management patterns:
///   Types: Identity, AccessControl, DataProcessing, Reporting  
///   AttackTypes: Tampering, UnauthorizedQuery, Replay, DenialOfService  
///   DefenseTypes: AccessControl, ImmutableCatalog, SignatureValidation, RateLimit, AuditLogging

enum CapCatalogType           { Identity, AccessControl, DataProcessing, Reporting }
enum CapCatalogAttackType     { Tampering, UnauthorizedQuery, Replay, DenialOfService }
enum CapCatalogDefenseType    { AccessControl, ImmutableCatalog, SignatureValidation, RateLimit, AuditLogging }

error CC__NotOwner();
error CC__AlreadyExists();
error CC__Immutable();
error CC__TooManyRequests();
error CC__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CATALOG
//    • ❌ no controls: anyone may add or modify entries → Tampering
////////////////////////////////////////////////////////////////////////////////
contract CapabilitiesCatalogVuln {
    mapping(uint256 => string) public catalog;

    event CapabilityAdded(
        address indexed who,
        uint256           id,
        string            desc,
        CapCatalogType    ctype,
        CapCatalogAttackType attack
    );
    event CapabilityQueried(
        address indexed who,
        uint256           id,
        CapCatalogType    ctype,
        CapCatalogAttackType attack
    );

    function addCapability(
        uint256 id,
        string calldata desc,
        CapCatalogType ctype
    ) external {
        catalog[id] = desc;
        emit CapabilityAdded(msg.sender, id, desc, ctype, CapCatalogAttackType.Tampering);
    }

    function getCapability(uint256 id, CapCatalogType ctype) external {
        // no access check
        emit CapabilityQueried(msg.sender, id, ctype, CapCatalogAttackType.UnauthorizedQuery);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates tampering, unauthorized queries, replay, DoS
////////////////////////////////////////////////////////////////////////////////
contract Attack_CapabilitiesCatalog {
    CapabilitiesCatalogVuln public target;
    uint256 public lastId;
    string  public lastDesc;
    CapCatalogType public lastType;

    constructor(CapabilitiesCatalogVuln _t) { target = _t; }

    function tamper(
        uint256 id,
        string calldata desc
    ) external {
        target.addCapability(id, desc, CapCatalogType.DataProcessing);
        lastId   = id;
        lastDesc = desc;
        lastType = CapCatalogType.DataProcessing;
    }

    function query(uint256 id) external {
        target.getCapability(id, CapCatalogType.Reporting);
    }

    function replay() external {
        target.addCapability(lastId, lastDesc, lastType);
    }

    function dos(uint256 baseId, uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            target.addCapability(baseId + i, "malicious", CapCatalogType.Identity);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may add or query
////////////////////////////////////////////////////////////////////////////////
contract CapabilitiesCatalogSafeAccess {
    mapping(uint256 => string) public catalog;
    address public owner;

    event CapabilityAdded(
        address indexed who,
        uint256           id,
        string            desc,
        CapCatalogType    ctype,
        CapCatalogDefenseType defense
    );
    event CapabilityQueried(
        address indexed who,
        uint256           id,
        CapCatalogType    ctype,
        CapCatalogDefenseType defense
    );

    modifier onlyOwner() {
        if (msg.sender != owner) revert CC__NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addCapability(
        uint256 id,
        string calldata desc,
        CapCatalogType ctype
    ) external onlyOwner {
        catalog[id] = desc;
        emit CapabilityAdded(msg.sender, id, desc, ctype, CapCatalogDefenseType.AccessControl);
    }

    function getCapability(
        uint256 id,
        CapCatalogType ctype
    ) external onlyOwner {
        emit CapabilityQueried(msg.sender, id, ctype, CapCatalogDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH IMMUTABILITY & RATE LIMIT
//    • ✅ Defense: ImmutableCatalog – entries can’t be overwritten  
//               RateLimit         – cap adds per block
////////////////////////////////////////////////////////////////////////////////
contract CapabilitiesCatalogSafeImmutable {
    mapping(uint256 => string) public catalog;
    mapping(uint256 => bool)   public exists;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public addsInBlock;
    uint256 public constant MAX_ADDS = 3;

    event CapabilityAdded(
        address indexed who,
        uint256           id,
        string            desc,
        CapCatalogType    ctype,
        CapCatalogDefenseType defense
    );

    error CC__TooManyRequests();

    function addCapability(
        uint256 id,
        string calldata desc,
        CapCatalogType ctype
    ) external {
        if (exists[id]) revert CC__Immutable();

        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            addsInBlock[msg.sender] = 0;
        }
        addsInBlock[msg.sender]++;
        if (addsInBlock[msg.sender] > MAX_ADDS) revert CC__TooManyRequests();

        catalog[id] = desc;
        exists[id]  = true;
        emit CapabilityAdded(msg.sender, id, desc, ctype, CapCatalogDefenseType.ImmutableCatalog);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin signature  
//               AuditLogging       – record every change
////////////////////////////////////////////////////////////////////////////////
contract CapabilitiesCatalogSafeAdvanced {
    mapping(uint256 => string) public catalog;
    address public signer;

    event CapabilityAdded(
        address indexed who,
        uint256           id,
        string            desc,
        CapCatalogType    ctype,
        CapCatalogDefenseType defense
    );
    event AuditLog(
        address indexed who,
        uint256           id,
        string            desc,
        CapCatalogType    ctype,
        CapCatalogDefenseType defense
    );

    error CC__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function addCapability(
        uint256 id,
        string calldata desc,
        CapCatalogType ctype,
        bytes calldata sig
    ) external {
        // verify signature over (id||desc||ctype)
        bytes32 h = keccak256(abi.encodePacked(id, desc, ctype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CC__InvalidSignature();

        catalog[id] = desc;
        emit CapabilityAdded(msg.sender, id, desc, ctype, CapCatalogDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, id, desc, ctype, CapCatalogDefenseType.AuditLogging);
    }
}
