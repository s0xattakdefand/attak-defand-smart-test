// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OneTimeSignatureSuite.sol
/// @notice On-chain analogues of “One-Time Signature” (OTS) schemes:
///   Types: Lamport, Winternitz, MerkleTree  
///   AttackTypes: KeyReuse, SignatureForgery, ReplayAttack  
///   DefenseTypes: SingleUseKey, HashChain, MerkleVerification, RateLimit  

enum OneTimeSignatureType       { Lamport, Winternitz, MerkleTree }
enum OneTimeSignatureAttackType { KeyReuse, SignatureForgery, ReplayAttack }
enum OneTimeSignatureDefenseType{ SingleUseKey, HashChain, MerkleVerification, RateLimit }

error OTS__NoKey();
error OTS__AlreadyUsed();
error OTS__InvalidSig();
error OTS__TooMany();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE OTS (no single-use enforcement)
//    • Attack: KeyReuse, ReplayAttack
////////////////////////////////////////////////////////////////////////////////
contract OTSVuln {
    mapping(address => bytes32) public pubKey;
    event Signed(
        address indexed who,
        bytes      message,
        bytes      signature,
        OneTimeSignatureType  stype,
        OneTimeSignatureAttackType attack
    );

    /// set public key once
    function setPubKey(bytes32 pk) external {
        pubKey[msg.sender] = pk;
    }

    /// sign: no tracking, allows reuse / replay
    function sign(bytes calldata message, bytes calldata sig, OneTimeSignatureType stype) external {
        // stub: emit as if valid
        emit Signed(msg.sender, message, sig, stype, OneTimeSignatureAttackType.KeyReuse);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates key reuse and forgery
////////////////////////////////////////////////////////////////////////////////
contract Attack_OTS {
    OTSVuln public target;
    constructor(OTSVuln _t) { target = _t; }

    function reuseSign(bytes calldata message, bytes calldata sig) external {
        target.sign(message, sig, OneTimeSignatureType.Lamport);
    }

    function forge(bytes calldata message) external {
        // attacker emits forged signature
        bytes memory fake = hex"deadbeef";
        target.sign(message, fake, OneTimeSignatureType.Lamport);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE SINGLE-USE KEY OTS
//    • Defense: SingleUseKey – mark key used once
////////////////////////////////////////////////////////////////////////////////
contract OTSSafeSingleUse {
    mapping(address => bytes32) public pubKey;
    mapping(address => bool)    public used;
    event Signed(
        address indexed who,
        bytes      message,
        OneTimeSignatureType  stype,
        OneTimeSignatureDefenseType defense
    );

    function setPubKey(bytes32 pk) external {
        pubKey[msg.sender] = pk;
        used[msg.sender] = false;
    }

    function sign(bytes calldata message, bytes calldata sig, OneTimeSignatureType stype) external {
        if (pubKey[msg.sender] == bytes32(0)) revert OTS__NoKey();
        if (used[msg.sender]) revert OTS__AlreadyUsed();
        // stub verify signature matches pubKey...
        used[msg.sender] = true;
        emit Signed(msg.sender, message, stype, OneTimeSignatureDefenseType.SingleUseKey);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE HASH-CHAIN OTS
//    • Defense: HashChain – derive next pubKey from chain, enforce forward-only
////////////////////////////////////////////////////////////////////////////////
contract OTSSafeHashChain {
    mapping(address => bytes32[]) public chain; // precomputed keys
    mapping(address => uint256)  public idx;
    event Signed(
        address indexed who,
        bytes      message,
        OneTimeSignatureType  stype,
        OneTimeSignatureDefenseType defense
    );

    /// initialize with full chain of length N
    function initChain(bytes32[] calldata keys) external {
        require(chain[msg.sender].length == 0, "already init");
        chain[msg.sender] = keys;
        idx[msg.sender] = 0;
    }

    function sign(bytes calldata message, bytes calldata sig, OneTimeSignatureType stype) external {
        uint i = idx[msg.sender];
        require(i < chain[msg.sender].length, "no key left");
        // stub verify sig against chain[msg][i]
        idx[msg.sender] = i + 1;
        emit Signed(msg.sender, message, stype, OneTimeSignatureDefenseType.HashChain);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE MERKLE-BASED OTS WITH RATE-LIMIT
//    • Defense: MerkleVerification + RateLimit
////////////////////////////////////////////////////////////////////////////////
contract OTSSafeMerkle {
    bytes32 public root; 
    mapping(bytes32 => bool) public usedLeaf;
    mapping(address => uint256) public lastBlock;
    uint256 public constant MAX_PER_BLOCK = 1;

    event Signed(
        address indexed who,
        bytes      message,
        OneTimeSignatureType  stype,
        OneTimeSignatureDefenseType defense
    );
    error OTS__TooMany();

    constructor(bytes32 _root) {
        root = _root;
    }

    /// user provides leaf, proof, signature
    function sign(
        bytes calldata message,
        bytes32 leaf,
        bytes32[] calldata proof,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number == lastBlock[msg.sender]) revert OTS__TooMany();
        lastBlock[msg.sender] = block.number;

        require(!usedLeaf[leaf], "leaf used");
        // verify merkle proof to root
        bytes32 h = leaf;
        for (uint i = 0; i < proof.length; i++) {
            if (h < proof[i]) h = keccak256(abi.encodePacked(h, proof[i]));
            else          h = keccak256(abi.encodePacked(proof[i], h));
        }
        require(h == root, "invalid proof");
        // stub verify signature against leaf...
        usedLeaf[leaf] = true;
        emit Signed(msg.sender, message, OneTimeSignatureType.MerkleTree, OneTimeSignatureDefenseType.MerkleVerification);
    }
}
