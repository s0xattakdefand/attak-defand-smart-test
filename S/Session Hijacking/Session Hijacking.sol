// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SessionHijackingSuite.sol
/// @notice On‑chain analogues of four Session Hijacking patterns:
///   1) Session Replay (no replay protection)  
///   2) Session Fixation (anyone can set victim’s session)  
///   3) Session Sniffing (session IDs leaked in events)  
///   4) Session Never‑Expire (no timeout)  

error SH__BadSig();
error SH__Replayed();
error SH__Unauthorized();
error SH__AlreadyRevealed();

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

//////////////////////////////////////////////////////////////////////////////
// 1) SESSION REPLAY
//    Stateless signed “session” exec: no nonce/expiry allows replay hijack
//////////////////////////////////////////////////////////////////////////////
contract SessionExecVuln {
    using ECDSALib for bytes32;
    event Exec(address indexed caller, bytes payload);

    function exec(bytes calldata payload, bytes calldata sig) external {
        bytes32 h = keccak256(payload).toEthSignedMessageHash();
        address signer = h.recover(sig);
        // ❌ no replay protection → can be called multiple times
        (bool ok,) = address(this).call(payload);
        require(ok, "call failed");
        emit Exec(signer, payload);
    }
}

contract Attack_SessionReplay {
    SessionExecVuln public target;
    bytes            public payload;
    bytes            public sig;

    constructor(SessionExecVuln _t, bytes memory _payload, bytes memory _sig) {
        target  = _t;
        payload = _payload;
        sig     = _sig;
    }

    function replay() external {
        target.exec(payload, sig);
        target.exec(payload, sig); // succeeds again
    }
}

contract SessionExecSafe {
    using ECDSALib for bytes32;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Exec(bytes payload,uint256 nonce,uint256 expiry)");
    mapping(uint256 => bool) public used;

    event Exec(address indexed signer, bytes payload, uint256 nonce);

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("SessionExecSafe"), block.chainid, address(this)
        ));
    }

    function exec(
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "Expired");
        if (used[nonce]) revert SH__Replayed();

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, keccak256(payload), nonce, expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer = digest.recover(sig);

        used[nonce] = true;
        (bool ok,) = address(this).call(payload);
        require(ok, "call failed");
        emit Exec(signer, payload, nonce);
    }
}

//////////////////////////////////////////////////////////////////////////////
// 2) SESSION FIXATION
//    On‑chain store: attacker sets victim’s session token
//////////////////////////////////////////////////////////////////////////////
contract SessionStoreVuln {
    mapping(address => bytes32) public sessionToken;

    function createSession(address user, bytes32 token) external {
        // ❌ anyone can fix victim’s session
        sessionToken[user] = token;
    }

    function validate(address user, bytes32 token) external view returns (bool) {
        return sessionToken[user] == token;
    }
}

contract Attack_SessionFixation {
    SessionStoreVuln public target;
    constructor(SessionStoreVuln _t) { target = _t; }
    function fix(address victim, bytes32 tok) external {
        target.createSession(victim, tok);
    }
}

contract SessionStoreSafe {
    mapping(address => bytes32) private sessionToken;
    event SessionCreated(address indexed user, bytes32 token);

    function createSession(bytes32 token) external {
        // ✅ only caller may create their own session
        require(sessionToken[msg.sender] == bytes32(0), "Already has session");
        sessionToken[msg.sender] = token;
        emit SessionCreated(msg.sender, token);
    }

    function validate(address user, bytes32 token) external view returns (bool) {
        return sessionToken[user] == token;
    }
}

//////////////////////////////////////////////////////////////////////////////
// 3) SESSION SNIFFING
//    Vulnerable: session IDs emitted in events, sniffable off‑chain
//////////////////////////////////////////////////////////////////////////////
contract SessionEventVuln {
    event Login(address indexed user, bytes32 sessionId);

    function login(bytes32 sessionId) external {
        emit Login(msg.sender, sessionId);
    }
}

contract Attack_SessionEventSniff {
    SessionEventVuln public target;
    constructor(SessionEventVuln _t) { target = _t; }
    function loginAndSniff(bytes32 sid) external {
        target.login(sid);
        // off‑chain observer sees the plain sessionId
    }
}

contract SessionEventSafe {
    event LoginHash(address indexed user, bytes32 sessionHash);

    function login(bytes32 sessionId) external {
        // ✅ emit only hash of session ID
        emit LoginHash(msg.sender, keccak256(abi.encodePacked(sessionId)));
    }
}

//////////////////////////////////////////////////////////////////////////////
// 4) SESSION NEVER‑EXPIRE
//    Vulnerable: issued session tokens have no expiry → hijack anytime
//////////////////////////////////////////////////////////////////////////////
contract SessionNeverExpireVuln {
    mapping(bytes32 => bool) public valid;

    function issue(bytes32 token) external {
        valid[token] = true;
    }

    function isValid(bytes32 token) external view returns (bool) {
        return valid[token];
    }
}

contract Attack_SessionNeverExpire {
    SessionNeverExpireVuln public target;
    bytes32 public token;
    constructor(SessionNeverExpireVuln _t, bytes32 _tok) {
        target = _t; token = _tok;
    }
    function hijack() external view returns (bool) {
        // succeeds even long after issue
        return target.isValid(token);
    }
}

contract SessionExpireSafe {
    mapping(bytes32 => uint256) public expiry;

    function issue(bytes32 token, uint256 duration) external {
        expiry[token] = block.timestamp + duration;
    }

    function isValid(bytes32 token) external view returns (bool) {
        return expiry[token] > block.timestamp;
    }
}
