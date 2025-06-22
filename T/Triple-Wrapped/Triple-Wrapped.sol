// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TripleWrappedSuite.sol
/// @notice On‑chain analogues of “Triple Wrapped” data patterns:
///   Types: FirstWrap, SecondWrap, ThirdWrap  
///   AttackTypes: OutOfOrderUnwrap, SpoofWrap  
///   DefenseTypes: StageValidation, AuthenticatedWrap  

enum TripleWrappedType        { FirstWrap, SecondWrap, ThirdWrap }
enum TripleWrappedAttackType  { OutOfOrderUnwrap, SpoofWrap }
enum TripleWrappedDefenseType { StageValidation, AuthenticatedWrap }

error TW__BadStage();
error TW__NotWrapped();
error TW__AlreadyWrapped();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE: unrestricted wrap/un‐wrap
///─────────────────────────────────────────────────────────────────────────────
contract TripleWrappedVuln {
    // stores the innermost payload per user
    mapping(address => bytes) public payload;

    // apply three wraps by caller in any order
    function wrap(TripleWrappedType stage, bytes calldata data) external {
        // ❌ no tracking of wrap order or validation
        payload[msg.sender] = data;
    }

    // unwrap returns whatever is stored, regardless of prior wraps
    function unwrap() external view returns (bytes memory) {
        return payload[msg.sender];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: out‑of‑order unwrap or spoof wrap
///─────────────────────────────────────────────────────────────────────────────
contract Attack_TripleWrapped {
    TripleWrappedVuln public target;
    constructor(TripleWrappedVuln _t) { target = _t; }

    // attacker calls unwrap without wrapping to steal default or stale data
    function outOfOrderUnwrap() external view returns (bytes memory) {
        return target.unwrap();
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE: enforce sequential stage validation
///─────────────────────────────────────────────────────────────────────────────
contract TripleWrappedSafe {
    mapping(address => bytes)  private _wrapped1;
    mapping(address => bytes)  private _wrapped2;
    mapping(address => bytes)  private _wrapped3;
    mapping(address => uint8)  public  stage;

    /// only allow wrap1 at stage 0
    function wrap1(bytes calldata data) external {
        if (stage[msg.sender] != 0) revert TW__BadStage();
        _wrapped1[msg.sender] = data;
        stage[msg.sender] = 1;
    }

    /// only allow wrap2 at stage 1
    function wrap2(bytes calldata data) external {
        if (stage[msg.sender] != 1) revert TW__BadStage();
        _wrapped2[msg.sender] = data;
        stage[msg.sender] = 2;
    }

    /// only allow wrap3 at stage 2
    function wrap3(bytes calldata data) external {
        if (stage[msg.sender] != 2) revert TW__BadStage();
        _wrapped3[msg.sender] = data;
        stage[msg.sender] = 3;
    }

    /// only allow unwrap when fully wrapped (stage == 3)
    function unwrap() external view returns (bytes memory) {
        if (stage[msg.sender] != 3) revert TW__NotWrapped();
        return _wrapped3[msg.sender];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) AUTHENTICATED SAFE: only owner may wrap/un‐wrap and one‑time wraps
///─────────────────────────────────────────────────────────────────────────────
contract TripleWrappedSafeAuth {
    mapping(address => bytes) public finalPayload;
    mapping(address => bool)  public wrapped;
    address public immutable owner;

    error TW__NotOwner();
    error TW__AlreadyWrapped();

    constructor() {
        owner = msg.sender;
    }

    /// only owner may set final wrapped payload once
    function wrap(bytes calldata data) external {
        if (msg.sender != owner) revert TW__NotOwner();
        if (wrapped[msg.sender])      revert TW__AlreadyWrapped();
        wrapped[msg.sender] = true;
        finalPayload[msg.sender] = data;
    }

    /// only owner may unwrap
    function unwrap() external view returns (bytes memory) {
        if (msg.sender != owner) revert TW__NotOwner();
        return finalPayload[msg.sender];
    }
}
