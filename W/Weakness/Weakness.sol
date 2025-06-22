// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WeaknessSuite.sol
/// @notice On‐chain analogues of “Weakness” identification and mitigation patterns:
///   Types: Architectural, Implementation, Configuration, Human  
///   AttackTypes: Exploitation, Misconfiguration, CodeInjection, SocialEngineering  
///   DefenseTypes: Hardening, CodeReview, PatchManagement, Training

enum WeaknessType           { Architectural, Implementation, Configuration, Human }
enum WeaknessAttackType     { Exploitation, Misconfiguration, CodeInjection, SocialEngineering }
enum WeaknessDefenseType    { Hardening, CodeReview, PatchManagement, Training }

error WK__NotAuthorized();
error WK__ReviewFailed();
error WK__PatchMissing();
error WK__TooManyAttempts();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SYSTEM
//    • ❌ no weakness tracking → any flaw may be exploited
////////////////////////////////////////////////////////////////////////////////
contract WeaknessVuln {
    event WeaknessObserved(
        address indexed who,
        bytes32          id,
        WeaknessType     wtype,
        WeaknessAttackType attack
    );

    function observeWeakness(bytes32 id, WeaknessType wtype) external {
        // no checks or recording
        emit WeaknessObserved(msg.sender, id, wtype, WeaknessAttackType.Exploitation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates exploiting or misconfiguring a weakness
////////////////////////////////////////////////////////////////////////////////
contract Attack_Weakness {
    WeaknessVuln public target;

    constructor(WeaknessVuln _t) {
        target = _t;
    }

    function exploit(bytes32 id) external {
        target.observeWeakness(id, WeaknessType.Implementation);
    }
    function misconfigure(bytes32 id) external {
        target.observeWeakness(id, WeaknessType.Configuration);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH HARDENING
//    • ✅ Defense: Hardening – require baseline scan before observation
////////////////////////////////////////////////////////////////////////////////
contract WeaknessSafeHardening {
    mapping(bytes32 => bool) public hardened;
    event WeaknessRecorded(
        address indexed who,
        bytes32          id,
        WeaknessType     wtype,
        WeaknessDefenseType defense
    );
    error WK__NotAuthorized();

    function applyHardening(bytes32 id) external {
        hardened[id] = true;
    }

    function observeWeakness(bytes32 id, WeaknessType wtype) external {
        if (!hardened[id]) revert WK__NotAuthorized();
        emit WeaknessRecorded(msg.sender, id, wtype, WeaknessDefenseType.Hardening);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH CODE REVIEW
//    • ✅ Defense: CodeReview – require reviewer signature on report
////////////////////////////////////////////////////////////////////////////////
contract WeaknessSafeReview {
    mapping(bytes32 => bool) public reviewed;
    address public reviewer;
    event WeaknessRecorded(
        address indexed who,
        bytes32          id,
        WeaknessType     wtype,
        WeaknessDefenseType defense
    );
    error WK__ReviewFailed();

    constructor(address _reviewer) {
        reviewer = _reviewer;
    }

    function markReviewed(
        bytes32 id,
        bytes calldata sig
    ) external {
        // verify reviewer signature over id
        bytes32 hash = keccak256(abi.encodePacked(id));
        bytes32 eth  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != reviewer) revert WK__ReviewFailed();
        reviewed[id] = true;
    }

    function observeWeakness(bytes32 id, WeaknessType wtype) external {
        if (!reviewed[id]) revert WK__ReviewFailed();
        emit WeaknessRecorded(msg.sender, id, wtype, WeaknessDefenseType.CodeReview);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH PATCH MANAGEMENT & TRAINING
//    • ✅ Defense: PatchManagement – record patches before observing  
//               Training – cap observations per user per block
////////////////////////////////////////////////////////////////////////////////
contract WeaknessSafeAdvanced {
    mapping(bytes32 => bool) public patched;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event WeaknessRecorded(
        address indexed who,
        bytes32          id,
        WeaknessType     wtype,
        WeaknessDefenseType defense
    );
    error WK__PatchMissing();
    error WK__TooManyAttempts();

    function applyPatch(bytes32 id) external {
        patched[id] = true;
    }

    function observeWeakness(bytes32 id, WeaknessType wtype) external {
        if (!patched[id]) revert WK__PatchMissing();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WK__TooManyAttempts();

        emit WeaknessRecorded(msg.sender, id, wtype, WeaknessDefenseType.Training);
    }
}
