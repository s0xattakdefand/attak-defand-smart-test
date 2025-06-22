// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SplitKeySuite.sol
/// @notice Four “Split Key” patterns illustrating common pitfalls in on‑chain
///         key splitting and hardened defenses:
///   1) Hard‑coded Splits  
///   2) Public Mapping Splits  
///   3) Bulk Split Flooding (DoS)  
///   4) Stale Share Expiry  

error SK__Unauthorized();
error SK__TooManySplits();
error SK__ShareExpired();

library ECDSALib {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes memory sig) internal pure returns (address a) {
        require(sig.length == 65, "ECDSA: bad sig length");
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

///////////////////////////////////////////////////////////////////////////////
// 1) HARD‑CODED SPLITS
//
//    • Vulnerable: secret split into two public constants → any caller XORs them
//    • Attack: read both halves via getters and reconstruct
//    • Defense: remove on‑chain key storage; derive ephemeral key via off‑chain signature
///////////////////////////////////////////////////////////////////////////////
contract HardcodedSplitVuln {
    bytes32 public constant SHARE_A =
        hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    bytes32 public constant SHARE_B =
        hex"5555555555555555555555555555555555555555555555555555555555555555";

    /// reconstructs the secret
    function reconstruct() external view returns (bytes32) {
        return SHARE_A ^ SHARE_B;
    }
}

/// attack simply calls reconstruct()
contract Attack_HardcodedSplit {
    HardcodedSplitVuln public target;
    constructor(HardcodedSplitVuln _t) { target = _t; }
    function steal() external view returns (bytes32) {
        return target.reconstruct();
    }
}

contract HardcodedSplitSafe {
    using ECDSALib for bytes32;

    address public immutable manager;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("DeriveSplit(uint256 nonce,uint256 expiry,uint256 id)");

    mapping(uint256 => bool) public usedNonce;

    constructor(address _mgr) {
        manager = _mgr;
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("HardcodedSplitSafe"), block.chainid, address(this)
        ));
    }

    /// no on‑chain key halves; derive per‑id secret off‑chain via manager signature
    function derive(
        uint256 nonce,
        uint256 expiry,
        uint256 id,
        bytes calldata sig
    ) external returns (bytes32) {
        require(block.timestamp <= expiry, "expired");
        require(!usedNonce[nonce], "replayed");
        // verify manager sig
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, nonce, expiry, id));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != manager) revert SK__Unauthorized();
        usedNonce[nonce] = true;
        // derive secret as keccak(manager, id, nonce, expiry)
        return keccak256(abi.encodePacked(manager, id, nonce, expiry));
    }
}

///////////////////////////////////////////////////////////////////////////////
// 2) PUBLIC MAPPING SPLITS
//
//    • Vulnerable: stores both shares in public mappings
//    • Attack: read mapping values and XOR
//    • Defense: make one half private and restrict access to reconstruct()
///////////////////////////////////////////////////////////////////////////////
contract MappingSplitVuln {
    mapping(uint256 => bytes32) public shareA;
    mapping(uint256 => bytes32) public shareB;

    function setShares(uint256 id, bytes32 a, bytes32 b) external {
        shareA[id] = a;
        shareB[id] = b;
    }
    function reconstruct(uint256 id) external view returns (bytes32) {
        return shareA[id] ^ shareB[id];
    }
}

contract Attack_MappingSplit {
    MappingSplitVuln public target;
    constructor(MappingSplitVuln _t) { target = _t; }
    function leak(uint256 id) external view returns (bytes32) {
        return target.reconstruct(id);
    }
}

contract MappingSplitSafe {
    mapping(uint256 => bytes32) public shareA;
    mapping(uint256 => bytes32) private shareB;
    address public immutable owner;
    error SK__NotOwner();

    constructor() {
        owner = msg.sender;
    }

    function setShareA(uint256 id, bytes32 a) external {
        if (msg.sender != owner) revert SK__NotOwner();
        shareA[id] = a;
    }
    function setShareB(uint256 id, bytes32 b) external {
        if (msg.sender != owner) revert SK__NotOwner();
        shareB[id] = b;
    }

    /// only owner may reconstruct the key
    function reconstruct(uint256 id) external view returns (bytes32) {
        if (msg.sender != owner) revert SK__NotOwner();
        return shareA[id] ^ shareB[id];
    }
}

///////////////////////////////////////////////////////////////////////////////
// 3) BULK SPLIT FLOODING (DoS)
//
//    • Vulnerable: unlimited calls to split() → unbounded storage growth
//    • Attack: spam many splits to exhaust gas/storage
//    • Defense: cap splits per caller
///////////////////////////////////////////////////////////////////////////////
contract BulkSplitVuln {
    mapping(address => uint256[]) public ids;
    mapping(uint256 => bytes32) public share;

    function split(uint256 id, bytes32 s) external {
        share[id] = s;
        ids[msg.sender].push(id);
    }
}

contract Attack_BulkSplit {
    BulkSplitVuln public target;
    constructor(BulkSplitVuln _t) { target = _t; }
    function flood(uint256[] calldata _ids, bytes32 s) external {
        for (uint i; i < _ids.length; i++) {
            target.split(_ids[i], s);
        }
    }
}

contract BulkSplitSafe {
    mapping(address => uint256[]) public ids;
    mapping(uint256 => bytes32) public share;
    uint256 public constant MAX_PER_USER = 10;
    error SK__TooManySplits();

    function split(uint256 id, bytes32 s) external {
        if (ids[msg.sender].length >= MAX_PER_USER) revert SK__TooManySplits();
        share[id] = s;
        ids[msg.sender].push(id);
    }
}

///////////////////////////////////////////////////////////////////////////////
// 4) STALE SHARE EXPIRY
//
//    • Vulnerable: shares never expire → stale data can be misused
//    • Attack: reconstruct key long after it should have been invalid
//    • Defense: attach expiry and reject expired shares
///////////////////////////////////////////////////////////////////////////////
contract ExpiringSplitVuln {
    mapping(uint256 => bytes32) public shareA;
    mapping(uint256 => bytes32) public shareB;

    function setShares(uint256 id, bytes32 a, bytes32 b) external {
        shareA[id] = a;
        shareB[id] = b;
    }
    function reconstruct(uint256 id) external view returns (bytes32) {
        return shareA[id] ^ shareB[id];
    }
}

contract ExpiringSplitSafe {
    struct Share { bytes32 v; uint256 expiry; }
    mapping(uint256 => Share) public shareA;
    mapping(uint256 => Share) public shareB;
    error SK__ShareExpired();

    function setShareA(uint256 id, bytes32 a, uint256 ttl) external {
        shareA[id] = Share(a, block.timestamp + ttl);
    }
    function setShareB(uint256 id, bytes32 b, uint256 ttl) external {
        shareB[id] = Share(b, block.timestamp + ttl);
    }

    function reconstruct(uint256 id) external view returns (bytes32) {
        Share memory A = shareA[id];
        Share memory B = shareB[id];
        if (block.timestamp > A.expiry || block.timestamp > B.expiry) {
            revert SK__ShareExpired();
        }
        return A.v ^ B.v;
    }
}
