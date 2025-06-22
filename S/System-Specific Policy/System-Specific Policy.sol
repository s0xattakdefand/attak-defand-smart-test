// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SystemSpecificPolicySuite.sol
/// @notice Four “System‑Specific Policy” patterns with vulnerabilities and hardened defenses:
///   1) Discretionary Access Control (DAC)  
///   2) Mandatory Access Control (MAC)  
///   3) Role‑Based Access Control (RBAC)  
///   4) Attribute‑Based Access Control (ABAC)  

error SS__Replayed();
error MAC__NotOwner();
error RBAC__NotAdmin();
error ABAC__BadSig();

library ECDSALib {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes memory sig) internal pure returns (address a) {
        require(sig.length == 65, "ECDSA: bad length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0, mload(add(sig,96)))
        }
        a = ecrecover(h, v, r, s);
        require(a != address(0), "ECDSA: invalid");
    }
}

////////////////////////////////////////////////////////////////////////
// 1) Discretionary Access Control (DAC)
//    • Vulnerable: anyone may grant permissions for any owner
////////////////////////////////////////////////////////////////////////
contract DACVuln {
    mapping(address => mapping(address => bool)) public permission;
    /// set permission on behalf of arbitrary owner
    function setPermission(address owner, address who, bool ok) external {
        permission[owner][who] = ok;
    }
    function access(address owner) external view returns (bool) {
        return permission[owner][msg.sender];
    }
}

/// Attack: forge a grant for victim → hijack access
contract Attack_DAC {
    DACVuln public dac;
    constructor(DACVuln _d) { dac = _d; }
    function hijack(address victim) external {
        dac.setPermission(victim, msg.sender, true);
    }
}

contract DACSafe {
    mapping(address => mapping(address => bool)) private _permission;
    event PermissionSet(address indexed owner, address indexed who, bool ok);
    /// only owner may grant
    function setPermission(address who, bool ok) external {
        _permission[msg.sender][who] = ok;
        emit PermissionSet(msg.sender, who, ok);
    }
    function access(address owner) external view returns (bool) {
        return _permission[owner][msg.sender];
    }
}

////////////////////////////////////////////////////////////////////////
// 2) Mandatory Access Control (MAC)
//    • Vulnerable: anyone can assign their own clearance/classification
////////////////////////////////////////////////////////////////////////
contract MACVuln {
    mapping(address => uint8) public clearance;
    mapping(bytes32 => uint8) public classification;
    function setClearance(uint8 lvl) external {
        clearance[msg.sender] = lvl;
    }
    function setClassification(bytes32 resource, uint8 lvl) external {
        classification[resource] = lvl;
    }
    function access(bytes32 resource) external view returns (bool) {
        return clearance[msg.sender] >= classification[resource];
    }
}

/// Attack: untrusted user self‑assigns highest clearance
contract Attack_MAC {
    MACVuln public mac;
    constructor(MACVuln _m) { mac = _m; }
    function escalate() external {
        mac.setClearance(type(uint8).max);
    }
}

contract MACSafe {
    mapping(address => uint8) public clearance;
    mapping(bytes32 => uint8) public classification;
    address public immutable owner;
    error MAC__NotOwner();
    modifier onlyOwner() {
        if (msg.sender != owner) revert MAC__NotOwner();
        _;
    }
    constructor() { owner = msg.sender; }
    function setClearance(address who, uint8 lvl) external onlyOwner {
        clearance[who] = lvl;
    }
    function setClassification(bytes32 resource, uint8 lvl) external onlyOwner {
        classification[resource] = lvl;
    }
    function access(bytes32 resource) external view returns (bool) {
        return clearance[msg.sender] >= classification[resource];
    }
}

////////////////////////////////////////////////////////////////////////
// 3) Role‑Based Access Control (RBAC)
//    • Vulnerable: grantRole unchecked → anyone can assign roles
////////////////////////////////////////////////////////////////////////
contract RBACVuln {
    mapping(bytes32 => mapping(address => bool)) public hasRole;
    function grantRole(bytes32 role, address who) external {
        hasRole[role][who] = true;
    }
    function restricted(bytes32 role) external view returns (string memory) {
        require(hasRole[role][msg.sender], "no role");
        return "ok";
    }
}

/// Attack: assign “SPECIAL” role to self
contract Attack_RBAC {
    RBACVuln public rbac;
    bytes32 public constant SPECIAL = keccak256("SPECIAL");
    constructor(RBACVuln _r) { rbac = _r; }
    function hijack() external {
        rbac.grantRole(SPECIAL, msg.sender);
    }
}

contract RBACSafe {
    mapping(bytes32 => mapping(address => bool)) public hasRole;
    mapping(bytes32 => bytes32)   public adminRole;
    bytes32 public constant DEFAULT_ADMIN = keccak256("DEFAULT_ADMIN");
    error RBAC__NotAdmin();
    constructor() {
        adminRole[DEFAULT_ADMIN] = DEFAULT_ADMIN;
        hasRole[DEFAULT_ADMIN][msg.sender] = true;
    }
    modifier onlyAdmin(bytes32 role) {
        bytes32 admin = adminRole[role];
        if (!hasRole[admin][msg.sender]) revert RBAC__NotAdmin();
        _;
    }
    function grantRole(bytes32 role, address who) external onlyAdmin(role) {
        hasRole[role][who] = true;
    }
    function restrict(bytes32 role) external view returns (string memory) {
        require(hasRole[role][msg.sender], "no role");
        return "ok";
    }
    function setRoleAdmin(bytes32 role, bytes32 newAdmin) external onlyAdmin(role) {
        adminRole[role] = newAdmin;
    }
}

////////////////////////////////////////////////////////////////////////
// 4) Attribute‑Based Access Control (ABAC)
//    • Vulnerable: anyone can spoof any user’s attributes
////////////////////////////////////////////////////////////////////////
contract ABACVuln {
    mapping(address => mapping(string => string)) public attribute;
    function setAttribute(address user, string calldata name, string calldata value) external {
        attribute[user][name] = value;
    }
    function access(string calldata name, string calldata value) external view returns (bool) {
        return keccak256(bytes(attribute[msg.sender][name])) == keccak256(bytes(value));
    }
}

/// Attack: spoof victim’s “role” attribute to “admin”
contract Attack_ABAC {
    ABACVuln public abac;
    constructor(ABACVuln _a) { abac = _a; }
    function spoof(address victim) external {
        abac.setAttribute(victim, "role", "admin");
    }
}

contract ABACSafe {
    using ECDSALib for bytes32;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Attr(address user,string name,string value,uint256 nonce,uint256 expiry)");
    mapping(uint256 => bool) public used;
    mapping(address => mapping(string => string)) private _attribute;
    error ABAC__BadSig();
    error ABAC__Replayed();
    error ABAC__Expired();

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("ABACSafe"), block.chainid, address(this)
        ));
    }

    /// @notice only the true user may sign their own attribute assignment
    function setAttribute(
        string calldata name,
        string calldata value,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry) revert ABAC__Expired();
        if (used[nonce])          revert ABAC__Replayed();

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH,
            msg.sender,
            keccak256(bytes(name)),
            keccak256(bytes(value)),
            nonce,
            expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != msg.sender) revert ABAC__BadSig();

        used[nonce] = true;
        _attribute[msg.sender][name] = value;
    }

    function access(string calldata name, string calldata value) external view returns (bool) {
        return keccak256(bytes(_attribute[msg.sender][name])) == keccak256(bytes(value));
    }
}
