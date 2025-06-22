// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

///─────────────────────────────────────────────────────────────────────────────
///                            SHARED ERRORS & LIBRARY
///─────────────────────────────────────────────────────────────────────────────
error Auth__Replayed();
error Auth__BadSig();
error KeyEx__BadAuth();
error MI__BadIntegrity();
error Chan__NoSession();
error Chan__Replayed();

library ECDSALib {
    /// @dev prefix & hash for eth_sign
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    /// @dev recover address from 65‑byte signature
    function recover(bytes32 h, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0, mload(add(sig,96)))
        }
        address a = ecrecover(h, v, r, s);
        require(a != address(0), "ECDSA: invalid");
        return a;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) CHALLENGE‑RESPONSE AUTH PROTOCOL
///─────────────────────────────────────────────────────────────────────────────

// Vulnerable: never invalidates challenges, so the same response can be replayed
contract AuthProtocolVuln {
    using ECDSALib for bytes32;
    address public manager;
    bytes32 public challenge;
    mapping(address=>bool) public authenticated;

    constructor(address _manager) { manager = _manager; }

    /// @notice Manager sets a fresh challenge off‑chain, then on‑chain
    function setChallenge(bytes32 c) external {
        require(msg.sender == manager, "Only manager");
        challenge = c;
    }

    /// @notice Client signs `challenge` and submits sig
    function authenticate(bytes calldata sig) external {
        bytes32 h = challenge.toEthSignedMessageHash();
        address signer = h.recover(sig);
        // no replay protection!
        if (signer != msg.sender) revert Auth__BadSig();
        authenticated[signer] = true;
    }
}

/// Attack: reuse the same signature twice
contract Attack_AuthReplay {
    AuthProtocolVuln public target;
    bytes            public sig;

    constructor(AuthProtocolVuln _t, bytes memory _sig) {
        target = _t;
        sig    = _sig;
    }

    function replay() external {
        target.authenticate(sig);
        target.authenticate(sig); // succeeds again
    }
}

// Safe: binds each response to a nonce+expiry so it cannot be replayed
contract AuthProtocolSafe {
    using ECDSALib for bytes32;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Auth(uint256 nonce,uint256 expiry)");
    mapping(uint256=>bool) public used;

    mapping(address=>bool) public authenticated;

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("AuthProtocolSafe"),
            block.chainid,
            address(this)
        ));
    }

    function authenticate(
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "Expired");
        if (used[nonce])           revert Auth__Replayed();

        // build EIP‑712 digest
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, nonce, expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer = digest.recover(sig);

        if (signer != msg.sender) revert Auth__BadSig();
        used[nonce] = true;
        authenticated[signer] = true;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) KEY‑EXCHANGE PROTOCOL
///─────────────────────────────────────────────────────────────────────────────

// Vulnerable: anyone can impersonate any party’s public key
contract KeyExchangeVuln {
    mapping(address=>bytes32) public pubKey;

    function setPubKey(address user, bytes32 pk) external {
        pubKey[user] = pk;
    }

    function sharedKey(address a, address b) external view returns (bytes32) {
        return keccak256(abi.encodePacked(pubKey[a], pubKey[b]));
    }
}

/// Attack: overwrite victim’s public key entry
contract Attack_KeyExchangeMitm {
    KeyExchangeVuln public target;
    constructor(KeyExchangeVuln _t) { target = _t; }

    function exploit(address victim, bytes32 fakePk) external {
        target.setPubKey(victim, fakePk);
    }
}

// Safe: requires each public key to be ECDSA‑signed by the claimed user
contract KeyExchangeSafe {
    using ECDSALib for bytes32;
    mapping(address=>bytes32) public pubKey;

    function setPubKey(
        address user,
        bytes32 pk,
        bytes calldata sig
    ) external {
        // verify user signed their own (user‖pk)
        bytes32 h = keccak256(abi.encodePacked(user, pk)).toEthSignedMessageHash();
        if (h.recover(sig) != user) revert KeyEx__BadAuth();
        pubKey[user] = pk;
    }

    function sharedKey(address a, address b) external view returns (bytes32) {
        return keccak256(abi.encodePacked(pubKey[a], pubKey[b]));
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) MESSAGE INTEGRITY PROTOCOL
///─────────────────────────────────────────────────────────────────────────────

// Vulnerable: no integrity check on stored messages
contract MsgIntegrityVuln {
    mapping(uint256=>bytes) public store;

    function storeMsg(uint256 id, bytes calldata msgData) external {
        store[id] = msgData;
    }
}

/// Attack: simply tamper with the stored message
contract Attack_MsgTamper {
    MsgIntegrityVuln public target;
    constructor(MsgIntegrityVuln _t) { target = _t; }

    function exploit(uint256 id, bytes calldata fake) external {
        target.storeMsg(id, fake);
    }
}

// Safe: enforce a keccak256 checksum on each message
contract MsgIntegritySafe {
    mapping(uint256=>bytes)   public store;
    mapping(uint256=>bytes32) public checksum;

    function storeMsg(
        uint256 id,
        bytes calldata msgData,
        bytes32 expectedHash
    ) external {
        if (keccak256(msgData) != expectedHash) revert MI__BadIntegrity();
        store[id]     = msgData;
        checksum[id]  = expectedHash;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SECURE CHANNEL (SESSION) PROTOCOL
///─────────────────────────────────────────────────────────────────────────────

// Vulnerable: no replay protection on session establishment
contract ChannelProtocolVuln {
    mapping(address=>uint256) public sessionOpen;

    function openSession(bytes calldata sig) external {
        // anyone with a valid signature can open, but sig never bound to nonce
        sessionOpen[msg.sender] = 1;
    }

    function useChannel() external view returns (bool) {
        return sessionOpen[msg.sender] == 1;
    }
}

/// Attack: open the same session twice
contract Attack_ChanReplay {
    ChannelProtocolVuln public target;
    bytes                 public sig;
    constructor(ChannelProtocolVuln _t, bytes memory _sig) {
        target = _t; sig = _sig;
    }
    function attack() external {
        target.openSession(sig);
        target.openSession(sig); // succeeds again
    }
}

// Safe: each session must be signed with a unique nonce+expiry
contract ChannelProtocolSafe {
    using ECDSALib for bytes32;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("OpenSession(uint256 nonce,uint256 expiry)");

    mapping(uint256=>bool) public used;
    mapping(address=>uint256) public sessionOpened;

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("ChannelProtocolSafe"), block.chainid, address(this)
        ));
    }

    function openSession(
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "Expired");
        if (used[nonce]) revert Chan__Replayed();

        bytes32 structHash = keccak256(abi.encode(TYPEHASH, nonce, expiry));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer = digest.recover(sig);
        require(signer == msg.sender, "Bad sig");

        used[nonce] = true;
        sessionOpened[msg.sender] = nonce;
    }

    function useChannel() external view returns (bool) {
        return sessionOpened[msg.sender] != 0;
    }
}
