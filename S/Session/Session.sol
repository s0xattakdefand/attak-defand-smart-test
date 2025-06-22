// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

//////////////////////////////////////////////////////////////
//                       SHARED ERRORS
//////////////////////////////////////////////////////////////
error Session__BadSig();
error Session__Expired();
error Session__Replayed();
error Store__Unauthorized();
error Store__Invalid();
error Proxy__NotOwner();
error Proxy__NotAllowed();
error Sig__Invalid();

//////////////////////////////////////////////////////////////
//                        SIG RECOVERY
//////////////////////////////////////////////////////////////
library SigLib {
    /// @dev "\x19Ethereum Signed Message:\n32"+hash
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address a) {
        if (sig.length != 65) revert Sig__Invalid();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(
            keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h)),
            v, r, s
        );
    }
}

//////////////////////////////////////////////////////////////
// 1. STATELESS SIGNED SESSION
//////////////////////////////////////////////////////////////
contract SessionSignedVuln {
    using SigLib for bytes32;
    address public immutable app;  // off‑chain signer/origin

    constructor(address _app) { app = _app; }

    /// ❌ no nonce or expiry—can replay forever
    function exec(bytes calldata payload, bytes calldata sig) external {
        bytes32 h = keccak256(payload);
        if (h.recover(sig) != app) revert Session__BadSig();
        (bool ok, ) = app.call(payload);
        require(ok, "call failed");
    }
}

/// Demo replay attack
contract Attack_SessionReplay {
    SessionSignedVuln public vuln;
    bytes           public payload;
    bytes           public sig;

    constructor(
        SessionSignedVuln _v,
        bytes memory _payload,
        bytes memory _sig
    ) {
        vuln    = _v;
        payload = _payload;
        sig     = _sig;
    }

    function replay() external {
        // succeeds repeatedly—no replay protection
        vuln.exec(payload, sig);
    }
}

contract SessionSignedSafe {
    using SigLib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Session(bytes payload,uint256 nonce,uint256 expiry)");

    address public immutable app;
    mapping(uint256 => bool) public usedNonce;

    constructor(address _app) {
        app    = _app;
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SessionSignedSafe"),
                block.chainid,
                address(this)
            )
        );
    }

    /// ✅ binds to nonce + expiry
    function exec(
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry)        revert Session__Expired();
        if (usedNonce[nonce])                revert Session__Replayed();

        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, keccak256(payload), nonce, expiry)
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN, structHash)
        );
        if (digest.recover(sig) != app) revert Session__BadSig();

        usedNonce[nonce] = true;
        (bool ok, ) = app.call(payload);
        require(ok, "call failed");
    }
}

//////////////////////////////////////////////////////////////
// 2. ON‑CHAIN SESSION REGISTRY
//////////////////////////////////////////////////////////////
contract SessionStoreVuln {
    mapping(address => bytes32) public userSession;

    /// ❌ anyone can forge a session for any user
    function createSession(address user, bytes32 id) external {
        userSession[user] = id;
    }
    function validateSession(address user, bytes32 id) external view returns (bool) {
        return userSession[user] == id;
    }
}

/// Demo session‑fixation attack
contract Attack_SessionFixation {
    SessionStoreVuln public store;
    constructor(SessionStoreVuln _s) { store = _s; }
    function fix(address victim, bytes32 id) external {
        // attacker sets session for victim
        store.createSession(victim, id);
    }
}

contract SessionStoreSafe {
    mapping(address => bytes32) private userSession;
    event SessionCreated(address indexed user, bytes32 id);
    event SessionRevoked(address indexed user, bytes32 id);

    /// ✅ only caller can create/revoke its own session
    function createSession(bytes32 id) external {
        if (userSession[msg.sender] != bytes32(0)) revert Store__Unauthorized();
        userSession[msg.sender] = id;
        emit SessionCreated(msg.sender, id);
    }

    function revokeSession() external {
        bytes32 id = userSession[msg.sender];
        if (id == bytes32(0)) revert Store__Invalid();
        delete userSession[msg.sender];
        emit SessionRevoked(msg.sender, id);
    }

    function validateSession(address user, bytes32 id) external view returns (bool) {
        return userSession[user] == id;
    }
}

//////////////////////////////////////////////////////////////
// 3. SESSION DELEGATION PROXY
//////////////////////////////////////////////////////////////
contract SessionProxyVuln {
    address public owner;
    uint256 public secret;

    constructor() { owner = msg.sender; }

    /// ❌ no auth, no whitelist—anyone can delegate any code
    function exec(address target, bytes calldata data) external {
        target.delegatecall(data);
    }

    function setSecret(uint256 v) external {
        secret = v;
    }
}

/// Demo delegate‑call exploit
contract Attack_SessionDelegation {
    SessionProxyVuln public proxy;
    constructor(SessionProxyVuln _p) { proxy = _p; }

    function pwn() external {
        // attacker changes proxy.secret via delegatecall
        bytes memory payload = abi.encodeWithSelector(
            SessionProxyVuln.setSecret.selector, uint256(123456)
        );
        proxy.exec(address(proxy), payload);
    }
}

contract SessionProxySafe {
    address public owner;
    mapping(bytes4 => bool) public allowed;

    error Proxy__NotOwner();
    error Proxy__NotAllowed();

    constructor() {
        owner = msg.sender;
    }

    /// ✅ owner whitelists specific function selectors
    function allowSelector(bytes4 sel) external {
        if (msg.sender != owner) revert Proxy__NotOwner();
        allowed[sel] = true;
    }

    /// ✅ only owner + whitelisted selectors
    function exec(address target, bytes calldata data) external {
        if (msg.sender != owner)            revert Proxy__NotOwner();
        bytes4 sel;
        assembly { sel := calldataload(data.offset) }
        if (!allowed[sel])                  revert Proxy__NotAllowed();
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }

    // demo state to be protected
    uint256 public secret;
    function setSecret(uint256 v) external {
        secret = v;
    }
}
