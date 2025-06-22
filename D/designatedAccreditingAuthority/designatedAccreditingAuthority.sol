// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DesignatedAccreditingAuthoritySuite.sol
/// @notice On‐chain analogues of “Designated Accrediting Authority” registry patterns:
///   Types: GovernmentAgency, PrivateCertifier, ISO, IndustryGroup  
///   AttackTypes: ForgedCertificate, RevocationOmission, UnauthorizedIssuance, Replay  
///   DefenseTypes: DigitalSignature, RevocationCheck, MultiPartyApproval, RateLimit, AuditLogging

enum AccredAuthorityType    { GovernmentAgency, PrivateCertifier, ISO, IndustryGroup }
enum AccredAttackType       { ForgedCertificate, RevocationOmission, UnauthorizedIssuance, Replay }
enum AccredDefenseType      { DigitalSignature, RevocationCheck, MultiPartyApproval, RateLimit, AuditLogging }

error DAA__NotAuthorized();
error DAA__AlreadyRegistered();
error DAA__Revoked();
error DAA__TooManyRequests();
error DAA__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE REGISTRY
//    • ❌ no checks: anyone may register or revoke → ForgedCertificate
////////////////////////////////////////////////////////////////////////////////
contract DAAVuln {
    mapping(bytes32 => address) public authority;
    event AuthorityRegistered(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredAttackType attack
    );
    event AuthorityRevoked(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredAttackType attack
    );

    function registerAuthority(
        bytes32 id,
        address addr,
        AccredAuthorityType atype
    ) external {
        authority[id] = addr;
        emit AuthorityRegistered(msg.sender, id, atype, AccredAttackType.ForgedCertificate);
    }

    function revokeAuthority(bytes32 id, AccredAuthorityType atype) external {
        delete authority[id];
        emit AuthorityRevoked(msg.sender, id, atype, AccredAttackType.RevocationOmission);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates forgery, omission, replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_DAA {
    DAAVuln public target;
    bytes32 public lastId;
    address public lastAddr;
    AccredAuthorityType public lastType;

    constructor(DAAVuln _t) { target = _t; }

    function forge(bytes32 id, address addr) external {
        target.registerAuthority(id, addr, AccredAuthorityType.PrivateCertifier);
        lastId   = id;
        lastAddr = addr;
        lastType = AccredAuthorityType.PrivateCertifier;
    }

    function omitRevocation(bytes32 id) external {
        // attacker can revoke without trace
        target.revokeAuthority(id, AccredAuthorityType.ISO);
    }

    function replayRegistration() external {
        target.registerAuthority(lastId, lastAddr, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: MultiPartyApproval – only owner may register/revoke
////////////////////////////////////////////////////////////////////////////////
contract DAASafeAccess {
    mapping(bytes32 => address) public authority;
    address public owner;

    event AuthorityRegistered(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredDefenseType defense
    );
    event AuthorityRevoked(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DAA__NotAuthorized();
        _;
    }

    function registerAuthority(
        bytes32 id,
        address addr,
        AccredAuthorityType atype
    ) external onlyOwner {
        authority[id] = addr;
        emit AuthorityRegistered(msg.sender, id, atype, AccredDefenseType.MultiPartyApproval);
    }

    function revokeAuthority(bytes32 id, AccredAuthorityType atype) external onlyOwner {
        delete authority[id];
        emit AuthorityRevoked(msg.sender, id, atype, AccredDefenseType.MultiPartyApproval);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH REVOCATION CHECK & RATE LIMIT
//    • ✅ Defense: RevocationCheck – cannot register revoked IDs  
//               RateLimit       – cap operations per block
////////////////////////////////////////////////////////////////////////////////
contract DAASafeValidation {
    mapping(bytes32 => address) public authority;
    mapping(bytes32 => bool)    public revoked;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 3;

    event AuthorityRegistered(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredDefenseType defense
    );
    event AuthorityRevoked(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredDefenseType defense
    );

    error DAA__TooManyRequests();

    function registerAuthority(
        bytes32 id,
        address addr,
        AccredAuthorityType atype
    ) external {
        if (revoked[id]) revert DAA__Revoked();

        _rateLimit();
        authority[id] = addr;
        emit AuthorityRegistered(msg.sender, id, atype, AccredDefenseType.RevocationCheck);
    }

    function revokeAuthority(bytes32 id, AccredAuthorityType atype) external {
        _rateLimit();
        revoked[id] = true;
        delete authority[id];
        emit AuthorityRevoked(msg.sender, id, atype, AccredDefenseType.RevocationCheck);
    }

    function _rateLimit() internal {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DAA__TooManyRequests();
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: DigitalSignature – require admin signature  
//               AuditLogging      – record every change
////////////////////////////////////////////////////////////////////////////////
contract DAASafeAdvanced {
    mapping(bytes32 => address) public authority;
    mapping(bytes32 => bool)    public revoked;
    address public signer;

    event AuthorityRegistered(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredDefenseType defense
    );
    event AuthorityRevoked(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredDefenseType defense
    );
    event AuditLog(
        address indexed who,
        bytes32           id,
        AccredAuthorityType atype,
        AccredDefenseType defense
    );

    error DAA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function registerAuthority(
        bytes32 id,
        address addr,
        AccredAuthorityType atype,
        bytes calldata sig
    ) external {
        _verifySig(abi.encodePacked(id, addr, atype), sig);
        authority[id] = addr;
        emit AuthorityRegistered(msg.sender, id, atype, AccredDefenseType.DigitalSignature);
        emit AuditLog(msg.sender, id, atype, AccredDefenseType.AuditLogging);
    }

    function revokeAuthority(
        bytes32 id,
        AccredAuthorityType atype,
        bytes calldata sig
    ) external {
        _verifySig(abi.encodePacked(id, atype), sig);
        revoked[id] = true;
        delete authority[id];
        emit AuthorityRevoked(msg.sender, id, atype, AccredDefenseType.DigitalSignature);
        emit AuditLog(msg.sender, id, atype, AccredDefenseType.AuditLogging);
    }

    function _verifySig(bytes memory payload, bytes calldata sig) internal view {
        bytes32 h = keccak256(payload);
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DAA__InvalidSignature();
    }
}
