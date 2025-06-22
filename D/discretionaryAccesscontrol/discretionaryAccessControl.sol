// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DiscretionaryAccessControlSuite.sol
/// @notice On‐chain analogues of “Discretionary Access Control” (DAC) patterns:
///   Types: OwnerBased, ACLBased, RBAC, DACMatrix  
///   AttackTypes: PrivilegeEscalation, UnauthorizedAccess, Tampering, Bypass  
///   DefenseTypes: OwnerCheck, ACLCheck, PermissionMatrix, RateLimit, SignatureValidation

enum DACType                 { OwnerBased, ACLBased, RBAC, DACMatrix }
enum DAttackType             { PrivilegeEscalation, UnauthorizedAccess, Tampering, Bypass }
enum DDefenseType            { OwnerCheck, ACLCheck, PermissionMatrix, RateLimit, SignatureValidation }

error DAC__NotOwner();
error DAC__NoACL();
error DAC__NotPermitted();
error DAC__TooManyRequests();
error DAC__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DAC MANAGER
//    • ❌ no checks: anyone may set or get → UnauthorizedAccess
////////////////////////////////////////////////////////////////////////////////
contract DACVuln {
    mapping(address => mapping(bytes32 => bytes)) public store;

    event DataSet(
        address indexed who,
        address indexed user,
        bytes32            key,
        DACType            dtype,
        DAttackType        attack
    );
    event DataGet(
        address indexed who,
        address indexed user,
        bytes32            key,
        DACType            dtype,
        DAttackType        attack
    );

    function setData(address user, bytes32 key, bytes calldata data, DACType dtype) external {
        store[user][key] = data;
        emit DataSet(msg.sender, user, key, dtype, DAttackType.UnauthorizedAccess);
    }
    function getData(address user, bytes32 key, DACType dtype) external view returns (bytes memory) {
        emit DataGet(msg.sender, user, key, dtype, DAttackType.UnauthorizedAccess);
        return store[user][key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates escalation, tampering, bypass
////////////////////////////////////////////////////////////////////////////////
contract Attack_DAC {
    DACVuln public target;
    address public victim;
    bytes32 public lastKey;
    bytes   public lastData;

    constructor(DACVuln _t, address _victim) {
        target = _t;
        victim = _victim;
    }

    function tamper(bytes32 key, bytes calldata fake) external {
        target.setData(victim, key, fake, DACType.OwnerBased);
        lastKey  = key;
        lastData = fake;
    }
    function bypass() external {
        target.setData(victim, lastKey, lastData, DACType.ACLBased);
    }
    function leak(bytes32 key) external {
        lastData = target.getData(victim, key, DACType.OwnerBased);
        lastKey  = key;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH OWNER CHECK
//    • ✅ Defense: OwnerCheck – only the user (owner) may set/get
////////////////////////////////////////////////////////////////////////////////
contract DACSafeOwner {
    mapping(address => mapping(bytes32 => bytes)) public store;

    event DataSet(
        address indexed who,
        bytes32            key,
        DACType            dtype,
        DDefenseType       defense
    );
    event DataGet(
        address indexed who,
        bytes32            key,
        DACType            dtype,
        DDefenseType       defense
    );

    function setData(bytes32 key, bytes calldata data, DACType dtype) external {
        store[msg.sender][key] = data;
        emit DataSet(msg.sender, key, dtype, DDefenseType.OwnerCheck);
    }
    function getData(bytes32 key, DACType dtype) external view returns (bytes memory) {
        emit DataGet(msg.sender, key, dtype, DDefenseType.OwnerCheck);
        return store[msg.sender][key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ACL CHECK & PERMISSION MATRIX + RATE LIMIT
//    • ✅ Defense: ACLCheck – allow listed addresses  
//               PermissionMatrix – custom user→op→key rules  
//               RateLimit – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DACSafeACL {
    mapping(address => mapping(bytes32 => bytes))                 public store;
    mapping(address => mapping(address => bool))                  public acl;
    mapping(address => mapping(bytes32 => mapping(address => bool))) public matrix;
    mapping(address => uint256)                                    public lastBlock;
    mapping(address => uint256)                                    public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event DataSet(
        address indexed who,
        address indexed user,
        bytes32            key,
        DACType            dtype,
        DDefenseType       defense
    );
    event DataGet(
        address indexed who,
        address indexed user,
        bytes32            key,
        DACType            dtype,
        DDefenseType       defense
    );

    error DAC__NoACL();
    error DAC__NotPermitted();
    error DAC__TooManyRequests();

    function grantACL(address user, bool ok) external {
        // stub: owner management
        acl[msg.sender][user] = ok;
    }
    function setMatrix(address user, bytes32 key, address actor, bool ok) external {
        matrix[msg.sender][key][actor] = ok;
    }

    function setData(address user, bytes32 key, bytes calldata data, DACType dtype) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DAC__TooManyRequests();

        if (!acl[user][msg.sender] && !matrix[user][key][msg.sender]) revert DAC__NotPermitted();
        store[user][key] = data;
        emit DataSet(msg.sender, user, key, dtype, DDefenseType.ACLCheck);
    }
    function getData(address user, bytes32 key, DACType dtype) external view returns (bytes memory) {
        if (!acl[user][msg.sender] && !matrix[user][key][msg.sender]) revert DAC__NotPermitted();
        emit DataGet(msg.sender, user, key, dtype, DDefenseType.PermissionMatrix);
        return store[user][key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & RATE LIMIT
//    • ✅ Defense: SignatureValidation – require user‐signed permit  
//               RateLimit           – cap signed ops per block
////////////////////////////////////////////////////////////////////////////////
contract DACSafeAdvanced {
    mapping(address => mapping(bytes32 => bytes)) public store;
    mapping(address => uint256)                public lastBlock;
    mapping(address => uint256)                public opsInBlock;
    address public signer;
    uint256 public constant MAX_OPS = 3;

    event DataSet(
        address indexed who,
        address indexed user,
        bytes32            key,
        DACType            dtype,
        DDefenseType       defense
    );
    event DataGet(
        address indexed who,
        address indexed user,
        bytes32            key,
        DACType            dtype,
        DDefenseType       defense
    );

    error DAC__TooManyRequests();
    error DAC__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function setData(
        address user,
        bytes32 key,
        bytes calldata data,
        DACType dtype,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DAC__TooManyRequests();

        // verify signature over (user||key||dtype)
        bytes32 h = keccak256(abi.encodePacked(user, key, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DAC__InvalidSignature();

        store[user][key] = data;
        emit DataSet(msg.sender, user, key, dtype, DDefenseType.SignatureValidation);
    }
    function getData(
        address user,
        bytes32 key,
        DACType dtype,
        bytes calldata sig
    ) external view returns (bytes memory) {
        // verify signature over (msg.sender||user||key||dtype)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, user, key, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DAC__InvalidSignature();

        emit DataGet(msg.sender, user, key, dtype, DDefenseType.RateLimit);
        return store[user][key];
    }
}
