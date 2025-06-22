// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

//////////////////////////////////////////////////////////////
//                       COMMON UTILITIES
//////////////////////////////////////////////////////////////
error SK__BadSig();
error SK__Replayed();
error SK__NotAuthorized();
error SK__TooEarly();

library SigLib {
    /// @dev Recover EOA from "\x19Ethereum Signed Message:\n32"+h
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address a) {
        if (sig.length != 65) revert SK__BadSig();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h)), v, r, s);
    }
}

//////////////////////////////////////////////////////////////
// 1) STATELESS SIGNED SESSION KEY
//////////////////////////////////////////////////////////////
contract SK_SignedVuln {
    using SigLib for bytes32;
    address public immutable authority;
    event Executed(address caller, bytes payload);

    constructor(address _authority) { authority = _authority; }

    /// ❌ No nonce/expiry → replayable forever
    function exec(bytes calldata payload, bytes calldata sig) external {
        bytes32 h = keccak256(payload);
        if (h.recover(sig) != authority) revert SK__BadSig();
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(msg.sender, payload);
    }
}

/// Demo replay attack
contract Attack_SK_SignedReplay {
    SK_SignedVuln public target;
    bytes            public payload;
    bytes            public sig;

    constructor(SK_SignedVuln _t, bytes memory _payload, bytes memory _sig) {
        target  = _t;
        payload = _payload;
        sig     = _sig;
    }

    function attack() external {
        // call twice with same sig
        target.exec(payload, sig);
        target.exec(payload, sig);
    }
}

contract SK_SignedSafe {
    using SigLib for bytes32;

    address public immutable authority;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Session(bytes payload,uint256 nonce,uint256 expiry)");
    mapping(uint256 => bool) public used;

    event Executed(address caller, bytes payload, uint256 nonce);

    constructor(address _authority) {
        authority = _authority;
        DOMAIN    = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SK_SignedSafe"),
                block.chainid,
                address(this)
            )
        );
    }

    /// ✅ Binds to nonce + expiry
    function exec(
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry) revert SK__TooEarly();
        if (used[nonce])          revert SK__Replayed();

        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, keccak256(payload), nonce, expiry)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN, structHash)
        );
        if (digest.recover(sig) != authority) revert SK__BadSig();

        used[nonce] = true;
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(msg.sender, payload, nonce);
    }
}

//////////////////////////////////////////////////////////////
// 2) TIME‑LOCKED SESSION KEY
//////////////////////////////////////////////////////////////
contract SK_TimelockVuln {
    mapping(address => bytes32) public sessionKey;
    event Registered(address who, bytes32 key);

    /// ❌ No delay → immediate use allowed
    function register(bytes32 key) external {
        sessionKey[msg.sender] = key;
        emit Registered(msg.sender, key);
    }

    function useKey(bytes32 key) external view returns (bool) {
        return sessionKey[msg.sender] == key;
    }
}

/// Demo “no-delay” exploit
contract Attack_SK_Timelock {
    SK_TimelockVuln public target;
    bytes32          public key;

    constructor(SK_TimelockVuln _t, bytes32 _key) {
        target = _t;
        key    = _key;
    }

    function attack() external {
        target.register(key);
        require(target.useKey(key), "should work immediately");
    }
}

contract SK_TimelockSafe {
    mapping(address => bytes32) public pending;
    mapping(address => uint256) public readyAt;
    mapping(address => bytes32) public sessionKey;
    uint256 public immutable delay;

    event Registered(address who, bytes32 key, uint256 readyAt);
    event Activated(address who, bytes32 key);

    constructor(uint256 _delay) {
        delay = _delay;
    }

    function register(bytes32 key) external {
        pending[msg.sender] = key;
        uint256 eta        = block.timestamp + delay;
        readyAt[msg.sender] = eta;
        emit Registered(msg.sender, key, eta);
    }

    function activate() external {
        if (block.timestamp < readyAt[msg.sender]) revert SK__TooEarly();
        sessionKey[msg.sender] = pending[msg.sender];
        delete pending[msg.sender];
        delete readyAt[msg.sender];
        emit Activated(msg.sender, sessionKey[msg.sender]);
    }

    function useKey(bytes32 key) external view returns (bool) {
        return sessionKey[msg.sender] == key;
    }
}

//////////////////////////////////////////////////////////////
// 3) ON‑CHAIN SESSION KEY REGISTRY
//////////////////////////////////////////////////////////////
contract SK_RegistryVuln {
    mapping(address => bytes32) public keyOf;
    event KeySet(address who, bytes32 key);

    /// ❌ Anyone can set for anyone
    function setKey(address who, bytes32 key) external {
        keyOf[who] = key;
        emit KeySet(who, key);
    }
}

/// Demo registry fixation
contract Attack_SK_RegistryFixation {
    SK_RegistryVuln public target;
    constructor(SK_RegistryVuln _t) { target = _t; }
    function attack(address victim, bytes32 key) external {
        target.setKey(victim, key);
    }
}

contract SK_RegistrySafe {
    mapping(address => bytes32) public keyOf;
    event KeySet(address who, bytes32 key);
    event KeyCleared(address who);

    /// ✅ Only caller can set/clear their key
    function setKey(bytes32 key) external {
        keyOf[msg.sender] = key;
        emit KeySet(msg.sender, key);
    }

    function clearKey() external {
        delete keyOf[msg.sender];
        emit KeyCleared(msg.sender);
    }
}

//////////////////////////////////////////////////////////////
// 4) MULTI‑SIG SESSION KEY
//////////////////////////////////////////////////////////////
contract SK_MultiSigVuln {
    using SigLib for bytes32;

    address[] public signers;
    uint256   public threshold;

    constructor(address[] memory _signers, uint256 _k) {
        require(_k > 0 && _k <= _signers.length, "bad k");
        signers   = _signers;
        threshold = _k;
    }

    /// ❌ No replay or expiry protection
    function exec(bytes calldata payload, bytes[] calldata sigs) external {
        bytes32 h = keccak256(payload);
        uint256 count;
        address last;
        for (uint256 i; i < sigs.length; i++) {
            address s = h.recover(sigs[i]);
            require(_isSigner(s) && s > last, "bad sig");
            last = s;
            count++;
        }
        require(count >= threshold, "threshold");
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
    }

    function _isSigner(address s) internal view returns (bool) {
        for (uint256 i; i < signers.length; i++) if (signers[i] == s) return true;
        return false;
    }
}

/// Demo insufficient‑sig exploit
contract Attack_SK_MultiSigFail {
    SK_MultiSigVuln public target;
    bytes           public payload;
    bytes[]         public sigs;

    constructor(SK_MultiSigVuln _t, bytes memory _payload, bytes[] memory _sigs) {
        target  = _t;
        payload = _payload;
        sigs    = _sigs;
    }

    function attack() external {
        // < threshold signatures → revert
        target.exec(payload, sigs);
    }
}

contract SK_MultiSigSafe {
    using SigLib for bytes32;

    address[] public signers;
    uint256   public immutable threshold;
    bytes32   public immutable DOMAIN;
    mapping(bytes32 => bool) public executed;

    error BadSig();
    error ThresholdNotMet();
    error Replayed();

    event Executed(bytes payload, bytes32 txHash);

    constructor(address[] memory _signers, uint256 _k) {
        require(_k > 0 && _k <= _signers.length, "bad k");
        signers   = _signers;
        threshold = _k;
        DOMAIN    = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SK_MultiSigSafe"),
                block.chainid,
                address(this)
            )
        );
    }

    function exec(
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes[] calldata sigs
    ) external {
        require(block.timestamp <= expiry, "expired");

        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Use(bytes payload,uint256 nonce,uint256 expiry)"),
                keccak256(payload),
                nonce,
                expiry
            )
        );
        bytes32 txHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (executed[txHash]) revert Replayed();

        address last;
        uint256 count;
        for (uint256 i; i < sigs.length; i++) {
            address s = txHash.recover(sigs[i]);
            if (s <= last || !_isSigner(s)) revert BadSig();
            last = s;
            count++;
        }
        if (count < threshold) revert ThresholdNotMet();

        executed[txHash] = true;
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(payload, txHash);
    }

    function _isSigner(address s) internal view returns (bool) {
        for (uint256 i; i < signers.length; i++) if (signers[i] == s) return true;
        return false;
    }
}
