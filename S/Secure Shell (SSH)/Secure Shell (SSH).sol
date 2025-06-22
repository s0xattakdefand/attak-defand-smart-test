// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*//////////////////////////////////////////////////////////////
                    SHARED LIB & ERROR DEFINITIONS
//////////////////////////////////////////////////////////////*/
error SSH_NotOwner();
error SSH_BadSig();
error SSH_Expired();
error SSH_Replayed();
error SSH_NotAdmin();
error SSH_TooSoon();
error SSH_RoleExists();

library SigLib {
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := shr(248, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(h, v, r, s);
    }
}

/*//////////////////////////////////////////////////////////////
                 INTERFACE FOR PLUG‑N‑PLAY COMMANDS
//////////////////////////////////////////////////////////////*/
interface ISecureShell {
    /// @notice Execute raw payload if caller (or verified sig) is authorised
    function exec(bytes calldata payload, bytes calldata sig) external;
}

/*//////////////////////////////////////////////////////////////
            1.  KEY‑BASED SECURE SHELL  (single owner)
//////////////////////////////////////////////////////////////*/
contract SSH_Key is ISecureShell {
    address public immutable owner;
    constructor(address _o) { owner = _o; }

    function exec(bytes calldata payload, bytes calldata /*sig*/) external override {
        if (msg.sender != owner) revert SSH_NotOwner();
        _run(payload);
    }

    /*------------- INTERNAL -------------*/
    function _run(bytes calldata payload) internal {
        (bool ok,) = address(this).call(payload);
        require(ok, "Cmd fail");
    }

    /*------------- DEMO TARGET CMD -------------*/
    uint256 public secret;
    function setSecret(uint256 n) external { secret = n; }
}

/* --- Attack: key theft (simply call exec as owner) --- */
contract Attack_KeyTheft {
    function pwn(SSH_Key shell, bytes calldata cmd) external {
        shell.exec(cmd, ""); // assume attacker controls owner's EO A
    }
}

/*//////////////////////////////////////////////////////////////
        2.  SESSION‑TOKEN SECURE SHELL  (nonce + expiry)
//////////////////////////////////////////////////////////////*/
contract SSH_Session is ISecureShell {
    using SigLib for bytes32;

    address public immutable admin;
    mapping(uint256 => bool) public usedNonce;

    bytes32 private immutable DOMAIN;

    struct Session { bytes payload; uint256 nonce; uint256 expire; }
    bytes32 constant TYPEHASH = keccak256("Session(bytes payload,uint256 nonce,uint256 expire)");

    constructor(address _admin) {
        admin = _admin;
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SSH_Session"), block.chainid, address(this)
            )
        );
    }

    function exec(bytes calldata payload, bytes calldata sig) external override {
        (uint256 nonce,uint256 exp) = abi.decode(sig[sig.length-64:], (uint256,uint256)); // last 64 bytes appended by off‑chain signer
        if (block.timestamp > exp) revert SSH_Expired();
        if (usedNonce[nonce]) revert SSH_Replayed();

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN,
                keccak256(abi.encode(TYPEHASH, keccak256(payload), nonce, exp))
            )
        );
        if (digest.recover(sig) != admin) revert SSH_BadSig();

        usedNonce[nonce] = true;
        _run(payload);
    }

    function _run(bytes calldata p) internal {
        (bool ok,) = address(this).call(p);
        require(ok);
    }

    /*------ demo command ------*/
    uint256 public count;
    function inc() external { unchecked { ++count; } }
}

/* --- Attack: replay old session token --- */
contract Attack_SessionReplay {
    function replay(SSH_Session shell, bytes calldata payload, bytes calldata oldSig) external {
        shell.exec(payload, oldSig); // reverts by nonce check
    }
}

/*//////////////////////////////////////////////////////////////
        3.  ROLE‑BASED + TIMELOCK SECURE SHELL
//////////////////////////////////////////////////////////////*/
contract SSH_Role is ISecureShell {
    using SigLib for bytes32;

    bytes32 public constant ADMIN = keccak256("ADMIN");
    uint256 public immutable delay;   // seconds
    address public guardian;

    mapping(bytes32 => uint256) public eta;  // command => unlock time
    mapping(bytes32 => bool)    public done;

    event Queued(bytes32 indexed cmd, uint256 eta);
    event Executed(bytes32 indexed cmd);

    constructor(address _admin, address _guardian, uint256 _delay) {
        _roles[_admin] = ADMIN;
        guardian      = _guardian;
        delay         = _delay;
    }

    /*-------------  SIMPLE RBAC -------------*/
    mapping(address => bytes32) private _roles;
    modifier only(bytes32 role) {
        if (_roles[msg.sender] != role) revert SSH_NotAdmin();
        _;
    }
    function grant(address a, bytes32 r) external only(ADMIN) {
        if (_roles[a] != 0) revert SSH_RoleExists();
        _roles[a] = r;
    }
    function revoke(address a) external only(ADMIN) { _roles[a] = 0; }

    /*-------------  TIMELOCK LOGIC -------------*/
    function queue(bytes calldata payload) external only(ADMIN) returns (bytes32 id) {
        id = keccak256(payload);
        eta[id] = block.timestamp + delay;
        emit Queued(id, eta[id]);
    }

    function exec(bytes calldata payload, bytes calldata /*sig*/) external override {
        bytes32 id = keccak256(payload);
        if (block.timestamp < eta[id]) revert SSH_TooSoon();
        if (done[id]) revert SSH_Replayed();
        done[id] = true;
        _run(payload);
        emit Executed(id);
    }

    /* guardian kills queued cmd */
    function cancel(bytes32 id) external {
        if (msg.sender != guardian) revert SSH_NotAdmin();
        delete eta[id];
    }

    function _run(bytes calldata p) internal {
        (bool ok,) = address(this).call(p);
        require(ok);
    }

    /*------ demo privileged state ------*/
    uint256 public value;
    function set(uint256 v) external only(ADMIN) { value = v; }
}

/* --- Attack: fast‑queue & execute before defenders notice --- */
contract Attack_RoleFastRun {
    function race(SSH_Role shell, bytes calldata cmd) external {
        shell.queue(cmd);      // queues
        // pretend mempool time‑warp; cannot exec yet due to delay
        shell.exec(cmd, "");   // reverts (TooSoon)
    }
}
