// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

///─────────────────────────────────────────────────────────────────────────────
///                              LIBRARY + ERRORS
///─────────────────────────────────────────────────────────────────────────────
error SigAnalysis__Invalid();
error SigAnalysis__Malleable();
error SigAnalysis__Replayed();
error SigAnalysis__DomainReuse();

library ECDSALib {
    /// secp256k1n
    uint256 private constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant HALF_N = N >> 1;

    /// prefix for eth_sign
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }

    /// recover ECDSA signer
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address a) {
        if (sig.length != 65) revert SigAnalysis__Invalid();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset,32))
            v := byte(0, calldataload(add(sig.offset,64)))
        }
        a = ecrecover(h, v, r, s);
        if (a == address(0)) revert SigAnalysis__Invalid();
    }

    /// check low‑S to prevent malleability
    function isLowS(bytes calldata sig) internal pure returns (bool) {
        bytes32 s;
        assembly { s := calldataload(add(sig.offset,32)) }
        return uint256(s) <= HALF_N;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) MALLEABILITY ANALYSIS
///─────────────────────────────────────────────────────────────────────────────
/// ❌ Vulnerable: accepts high‑S malleable signatures
contract SigMalVuln {
    using ECDSALib for bytes32;

    /// @notice returns true if signature “valid” (no low‑S check)
    function analyze(bytes32 msgHash, bytes calldata sig) external pure returns (address) {
        bytes32 h = msgHash.toEthSignedMessageHash();
        return h.recover(sig);
    }
}

/// Attack: supply both low‑S and high‑S versions
contract Attack_SigMal {
    SigMalVuln public vuln;
    bytes      public lowSig;
    bytes      public highSig;

    constructor(SigMalVuln _v) { vuln = _v; }

    function setSigs(bytes calldata _low, bytes calldata _high) external {
        lowSig  = _low;
        highSig = _high;
    }

    function test(bytes32 hash) external view returns (address a1, address a2) {
        a1 = vuln.analyze(hash, lowSig);
        a2 = vuln.analyze(hash, highSig); // succeeds despite malleable high‑S
    }
}

/// ✅ Hardened: rejects high‑S signatures
contract SigMalSafe {
    using ECDSALib for bytes32;

    function analyze(bytes32 msgHash, bytes calldata sig) external pure returns (address) {
        bytes32 h = msgHash.toEthSignedMessageHash();
        address a = h.recover(sig);
        if (!ECDSALib.isLowS(sig)) revert SigAnalysis__Malleable();
        return a;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) REPLAY ANALYSIS
///─────────────────────────────────────────────────────────────────────────────
/// ❌ Vulnerable: no nonce check → same signature replayable forever
contract SigReplayVuln {
    using ECDSALib for bytes32;

    function analyze(
        bytes32 msgHash,
        uint256 nonce,
        bytes calldata sig
    ) external pure returns (address) {
        bytes32 h = keccak256(abi.encodePacked(msgHash, nonce)).toEthSignedMessageHash();
        return h.recover(sig);
    }
}

/// Attack: replay identical (hash,nonce,sig) twice
contract Attack_SigReplay {
    SigReplayVuln public vuln;
    bytes      public sig;
    bytes32    public hash;
    uint256    public nonce;

    constructor(SigReplayVuln _v) { vuln = _v; }

    function set(bytes32 _h, uint256 _n, bytes calldata _s) external {
        hash  = _h;
        nonce = _n;
        sig   = _s;
    }

    function test() external view returns (address a1, address a2) {
        a1 = vuln.analyze(hash, nonce, sig);
        a2 = vuln.analyze(hash, nonce, sig); // still succeeds
    }
}

/// ✅ Hardened: tracks used nonces to block replays
contract SigReplaySafe {
    using ECDSALib for bytes32;
    mapping(uint256 => bool) public used;

    function analyze(
        bytes32 msgHash,
        uint256 nonce,
        bytes calldata sig
    ) external returns (address) {
        if (used[nonce]) revert SigAnalysis__Replayed();
        bytes32 h = keccak256(abi.encodePacked(msgHash, nonce)).toEthSignedMessageHash();
        address a = h.recover(sig);
        used[nonce] = true;
        return a;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) DOMAIN‑COLLISION ANALYSIS (EIP‑712)
/**────────────────────────────────────────────────────────────────────────────
❌ Vulnerable: uses only “name” in domain → same domain across contracts collides
*/
contract TypedDataVuln {
    using ECDSALib for bytes32;

    bytes32 public DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Exec(bytes payload,uint256 nonce)");

    constructor(string memory name) {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name)"),
            keccak256(bytes(name))
        ));
    }

    function analyze(
        bytes calldata payload,
        uint256     nonce,
        bytes calldata sig
    ) external view returns (address) {
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, keccak256(payload), nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        return digest.recover(sig);
    }
}

/// Attack: cross‑contract replay using same “name”
contract Attack_TypedDataCross {
    TypedDataVuln public a;
    TypedDataVuln public b;
    bytes       public payload;
    uint256     public nonce;
    bytes       public sig;

    constructor(
        TypedDataVuln _a,
        TypedDataVuln _b,
        bytes memory _p,
        uint256 _n,
        bytes memory _s
    ) {
        a = _a; b = _b;
        payload = _p; nonce = _n; sig = _s;
    }

    function test() external view returns (address ra, address rb) {
        ra = a.analyze(payload, nonce, sig);
        rb = b.analyze(payload, nonce, sig); // succeeds across both
    }
}

/// ✅ Hardened: full EIP‑712 domain prevents collision
contract TypedDataSafe {
    using ECDSALib for bytes32;

    bytes32 public DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Exec(bytes payload,uint256 nonce)");

    constructor(string memory name, string memory version) {
        DOMAIN = keccak256(abi.encode(
            keccak256(
                "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            ),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            block.chainid,
            address(this)
        ));
    }

    function analyze(
        bytes calldata payload,
        uint256     nonce,
        bytes calldata sig
    ) external view returns (address) {
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, keccak256(payload), nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        return digest.recover(sig);
    }
}
