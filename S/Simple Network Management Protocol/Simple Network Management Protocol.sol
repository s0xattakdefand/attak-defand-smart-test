// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

///─────────────────────────────────────────────────────────────────────────────
///                              SHARED ERRORS
///─────────────────────────────────────────────────────────────────────────────
error SNMP__Unauthorized();
error SNMP__BulkTooLarge();
error SNMP__BadSignature();
error SNMP__Replayed();

///─────────────────────────────────────────────────────────────────────────────
///                           ECDSA RECOVERY LIBRARY
///─────────────────────────────────────────────────────────────────────────────
library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address a) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset,32))
            v := byte(0, calldataload(add(sig.offset,64)))
        }
        a = ecrecover(h, v, r, s);
        require(a != address(0), "invalid sig");
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) UNAUTHENTICATED GET/SET (VULN vs SAFE)
///─────────────────────────────────────────────────────────────────────────────
contract SNMPNoAuthVuln {
    mapping(uint => bytes) public store;
    event Set(uint indexed oid, bytes val);

    function get(uint oid) external view returns (bytes memory) {
        return store[oid];
    }
    function set(uint oid, bytes calldata val) external {
        store[oid] = val;
        emit Set(oid, val);
    }
}

/// Attack: anyone calls `set(...)`
contract Attack_SNMPNoAuth {
    SNMPNoAuthVuln public target;
    constructor(SNMPNoAuthVuln _t) { target = _t; }
    function exploit(uint oid, bytes calldata val) external {
        target.set(oid, val);
    }
}

/// Safe: only ECDSA‑signed SETs by `manager`
contract SNMPSigAuthSafe {
    using ECDSA for bytes32;

    address public immutable manager;
    mapping(uint => bytes) public store;
    mapping(uint => bool) public usedNonce;

    event Set(uint indexed oid, address sender);

    constructor(address _manager) {
        manager = _manager;
    }

    /// @notice `sig` must be an eth_sign of hash(oid,val,nonce,expiry)
    function set(
        uint oid,
        bytes calldata val,
        uint nonce,
        uint expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry) revert SNMP__Unauthorized();
        if (usedNonce[nonce])         revert SNMP__Replayed();

        bytes32 h = keccak256(abi.encode(oid, val, nonce, expiry));
        bytes32 digest = h.toEthSignedMessageHash();
        if (digest.recover(sig) != manager) revert SNMP__Unauthorized();

        usedNonce[nonce] = true;
        store[oid] = val;
        emit Set(oid, msg.sender);
    }

    function get(uint oid) external view returns (bytes memory) {
        return store[oid];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) BULK GET FLOOD (VULN vs SAFE)
///─────────────────────────────────────────────────────────────────────────────
contract SNMPBulkVuln {
    mapping(uint => bytes) public store;
    event BulkGot(address indexed who, uint count);

    function bulkGet(uint[] calldata oids) external view returns (bytes[] memory) {
        bytes[] memory out = new bytes[](oids.length);
        for (uint i; i < oids.length; i++) {
            out[i] = store[oids[i]];
        }
        // gas exhaustion possible if oids.length is huge
        return out;
    }
}

/// Attack: pass a massive array → DOS
contract Attack_SNMPBulk {
    SNMPBulkVuln public target;
    constructor(SNMPBulkVuln _t) { target = _t; }
    function flood(uint n) external view returns (bytes[] memory) {
        uint[] memory oids = new uint[](n);
        return target.bulkGet(oids);
    }
}

contract SNMPBulkSafe {
    mapping(uint => bytes) public store;
    uint public constant MAX_BULK = 50;

    function bulkGet(uint[] calldata oids) external view returns (bytes[] memory) {
        if (oids.length > MAX_BULK) revert SNMP__BulkTooLarge();
        bytes[] memory out = new bytes[](oids.length);
        for (uint i; i < oids.length; i++) {
            out[i] = store[oids[i]];
        }
        return out;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SNMPv3 USM (no replay protection)
///─────────────────────────────────────────────────────────────────────────────
contract SNMPv3Vuln {
    using ECDSA for bytes32;

    address public immutable user;
    mapping(uint => bytes) public store;

    function getV3(uint oid, uint msgId, bytes calldata sig)
        external view returns (bytes memory)
    {
        bytes32 h = keccak256(abi.encode(oid, msgId));
        // ❌ no check for reused msgId
        require(h.toEthSignedMessageHash().recover(sig) == user, "bad sig");
        return store[oid];
    }
}

/// Attack: replay same (msgId,sig) → succeeds repeatedly
contract Attack_SNMPv3Replay {
    SNMPv3Vuln public target;
    uint  public oid;
    uint  public msgId;
    bytes public sig;
    constructor(SNMPv3Vuln _t, uint _oid, uint _mid, bytes memory _sig) {
        target = _t; oid = _oid; msgId = _mid; sig = _sig;
    }
    function replay() external view returns (bytes memory) {
        return target.getV3(oid, msgId, sig);
    }
}

contract SNMPv3Safe {
    using ECDSA for bytes32;

    address public immutable user;
    mapping(uint => bool) public seenMsg;
    mapping(uint => bytes) public store;

    constructor(address _user) {
        user = _user;
    }

    function getV3(
        uint oid,
        uint msgId,
        uint expiry,
        bytes calldata sig
    ) external returns (bytes memory) {
        if (block.timestamp > expiry)        revert SNMP__Unauthorized();
        if (seenMsg[msgId])                  revert SNMP__Replayed();

        bytes32 h = keccak256(abi.encode(oid, msgId, expiry));
        if (h.toEthSignedMessageHash().recover(sig) != user) revert SNMP__Unauthorized();

        seenMsg[msgId] = true;
        return store[oid];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) VACM ACCESS CONTROL
///─────────────────────────────────────────────────────────────────────────────
contract SNMPVACMVuln {
    mapping(uint => bytes) public store;
    function get(uint oid) external view returns (bytes memory) {
        return store[oid];       // ❌ no ACL
    }
    function set(uint oid, bytes calldata val) external {
        store[oid] = val;        // ❌ no ACL
    }
}

/// Attack: read/set unauthorized OIDs
contract Attack_SNMPVACM {
    SNMPVACMVuln public target;
    constructor(SNMPVACMVuln _t) { target = _t; }
    function leak(uint oid) external view returns (bytes memory) {
        return target.get(oid);
    }
    function corrupt(uint oid, bytes calldata val) external {
        target.set(oid, val);
    }
}

/// Safe: per‑OID ACL mapping
contract SNMPVACMSafe {
    mapping(address => mapping(uint => bool)) public allowed;
    mapping(uint => bytes)                 public store;

    event Set(uint indexed oid, address indexed who);
    event Get(uint indexed oid, address indexed who);

    /// @notice grant `who` permission for `oid`
    function grant(address who, uint oid) external {
        allowed[who][oid] = true;
    }

    function get(uint oid) external view returns (bytes memory) {
        if (!allowed[msg.sender][oid]) revert SNMP__Unauthorized();
        return store[oid];
    }
    function set(uint oid, bytes calldata val) external {
        if (!allowed[msg.sender][oid]) revert SNMP__Unauthorized();
        store[oid] = val;
        emit Set(oid, msg.sender);
    }
}
