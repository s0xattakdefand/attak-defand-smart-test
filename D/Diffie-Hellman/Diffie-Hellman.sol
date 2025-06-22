// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DiffieHellmanSuite.sol
/// @notice On‑chain analogues of “Diffie–Hellman” key exchange patterns:
///   Types: StaticStatic, EphemeralStatic, EphemeralEphemeral  
///   AttackTypes: MitM, Replay, ParameterTampering  
///   DefenseTypes: AuthenticatedExchange, KeyConfirmation, ParameterValidation  

enum DiffieHellmanType          { StaticStatic, EphemeralStatic, EphemeralEphemeral }
enum DiffieHellmanAttackType    { MitM, Replay, ParameterTampering }
enum DiffieHellmanDefenseType   { AuthenticatedExchange, KeyConfirmation, ParameterValidation }

error DH__NotOwner();
error DH__BadSignature();
error DH__InvalidParams();
error DH__NoConfirmation();
error DH__ReplayDetected();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE EXCHANGE (no auth, no replay protection)
//
//    • any attacker can MITM by substituting parameters
//    • AttackType: MitM, ParameterTampering
////////////////////////////////////////////////////////////////////////////////
contract DiffieHellmanVuln {
    uint256 public p;
    uint256 public g;
    mapping(address => uint256) public pubKey;  // public exponentiations

    event ParamsSet(address indexed who, uint256 p_, uint256 g_, DiffieHellmanAttackType attack);
    event PubKeySent(address indexed who, uint256 pub, DiffieHellmanAttackType attack);
    event SecretComputed(address indexed who, bytes32 secret, DiffieHellmanAttackType attack);

    function setParams(uint256 p_, uint256 g_) external {
        p = p_; g = g_;
        emit ParamsSet(msg.sender, p_, g_, DiffieHellmanAttackType.ParameterTampering);
    }

    function sendPubKey(uint256 pub) external {
        pubKey[msg.sender] = pub % p;
        emit PubKeySent(msg.sender, pub, DiffieHellmanAttackType.MitM);
    }

    function computeSecret(address peer) external {
        // naive: shared = peerPub ^ ownPriv mod p -- stub via keccak
        bytes32 secret = keccak256(abi.encodePacked(pubKey[peer], pubKey[msg.sender]));
        emit SecretComputed(msg.sender, secret, DiffieHellmanAttackType.Replay);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB (MITM & replay)
//
////////////////////////////////////////////////////////////////////////////////
contract Attack_DiffieHellman {
    DiffieHellmanVuln public target;
    uint256            public fakePub;

    constructor(DiffieHellmanVuln _t, uint256 _fakePub) {
        target   = _t;
        fakePub  = _fakePub;
    }

    function interceptParams(uint256 p_, uint256 g_) external {
        // attacker substitutes its own params
        target.setParams(p_, g_);
    }

    function interceptPubKey(address from) external {
        // attacker sends fake public key to each party
        target.sendPubKey(fakePub);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE AUTHENTICATED EXCHANGE
//
//    • Defense: ParameterValidation & AuthenticatedExchange
//    • require signatures over (p,g) and pub keys
////////////////////////////////////////////////////////////////////////////////
contract DiffieHellmanSafeAuth {
    address public owner;
    uint256 public p;
    uint256 public g;
    mapping(address => uint256) public pubKey;
    mapping(bytes32 => bool)    private _usedNonce;

    event ParamsSet(address indexed who, uint256 p_, uint256 g_, DiffieHellmanDefenseType defense);
    event PubKeySent(address indexed who, uint256 pub, DiffieHellmanDefenseType defense);
    event SecretConfirmed(address indexed who, bytes32 secret, DiffieHellmanDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// only owner may set global parameters, with signature check
    function setParams(uint256 p_, uint256 g_, bytes calldata sig) external {
        // signature over abi.encodePacked("DH_PARAMS", p_, g_)
        bytes32 msgHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",
                              keccak256(abi.encodePacked("DH_PARAMS", p_, g_))));
        address signer = recover(msgHash, sig);
        if (signer != owner) revert DH__BadSignature();
        p = p_; g = g_;
        emit ParamsSet(msg.sender, p_, g_, DiffieHellmanDefenseType.AuthenticatedExchange);
    }

    /// participants send ephemeral pub keys, signed
    function sendPubKey(uint256 pub, bytes calldata sig, uint256 nonce) external {
        // replay protection
        bytes32 nkey = keccak256(abi.encodePacked(msg.sender, nonce));
        if (_usedNonce[nkey]) revert DH__ReplayDetected();
        _usedNonce[nkey] = true;

        // signature over abi.encodePacked("DH_PUB", msg.sender, pub, nonce)
        bytes32 msgHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32",
                              keccak256(abi.encodePacked("DH_PUB", msg.sender, pub, nonce))));
        address signer = recover(msgHash, sig);
        if (signer != msg.sender) revert DH__BadSignature();

        pubKey[msg.sender] = pub % p;
        emit PubKeySent(msg.sender, pub, DiffieHellmanDefenseType.AuthenticatedExchange);
    }

    /// compute and confirm secret via sending HMAC
    function confirmSecret(address peer, bytes32 hmac) external {
        bytes32 secret = keccak256(abi.encodePacked(pubKey[peer], pubKey[msg.sender]));
        // simple HMAC: keccak256(secret || msg.sender)
        bytes32 expected = keccak256(abi.encodePacked(secret, peer));
        if (expected != hmac) revert DH__BadSignature();
        emit SecretConfirmed(msg.sender, secret, DiffieHellmanDefenseType.KeyConfirmation);
    }

    /// ecrecover helper
    function recover(bytes32 h, bytes memory s) internal pure returns (address) {
        (uint8 v, bytes32 r, bytes32 ss) = abi.decode(s, (uint8, bytes32, bytes32));
        return ecrecover(h, v, r, ss);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE PARAMETER VALIDATION + EPHEMERAL KEY
//
//    • Defense: ParameterValidation
//    • require p,g be prime stub and use ephemeral keys only
////////////////////////////////////////////////////////////////////////////////
contract DiffieHellmanSafeParams {
    uint256 public p;
    uint256 public g;
    mapping(address => uint256) public ephPub;
    event ParamsSet(uint256 p_, uint256 g_, DiffieHellmanDefenseType defense);
    event EphKeySent(address indexed who, uint256 pub, DiffieHellmanDefenseType defense);

    /// require simple stub prime check: g>1 and p>g
    function setParams(uint256 p_, uint256 g_) external {
        if (p_ <= g_ || g_ <= 1) revert DH__InvalidParams();
        p = p_; g = g_;
        emit ParamsSet(p_, g_, DiffieHellmanDefenseType.ParameterValidation);
    }

    function sendEphKey(uint256 pub) external {
        // require pub < p
        if (pub == 0 || pub >= p) revert DH__InvalidParams();
        ephPub[msg.sender] = pub;
        emit EphKeySent(msg.sender, pub, DiffieHellmanDefenseType.ParameterValidation);
    }
}
