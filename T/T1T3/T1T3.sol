// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice “Split‑Horizon” for T‑Carrier lines: T1 and T3 analogues in Solidity

//─────────────────────────────────────────────────────────────────────────────
// TYPES FOR T1
//─────────────────────────────────────────────────────────────────────────────
/// T1 “line” variants
enum T1LineType { Full, Fractional, Extended }
/// Common attack vectors on T1
enum T1AttackType { FramingSlip, BitStuffing, LineCodeViolation }
/// Defense mechanisms for T1
enum T1DefenseType { FramingCheck, CRCValidation, B8ZSEnforcement }

//─────────────────────────────────────────────────────────────────────────────
// VULNERABLE T1 CONFIGURATION (no access control, no validation)
//─────────────────────────────────────────────────────────────────────────────
contract T1ConfigVuln {
    mapping(T1LineType => bool) public enabled;
    event T1Attack(T1AttackType attackType);

    /// ❌ anyone may enable any T1 line type, and we log a generic attack event
    function enableLine(T1LineType t) external {
        enabled[t] = true;
        emit T1Attack(T1AttackType.LineCodeViolation);
    }
}

//─────────────────────────────────────────────────────────────────────────────
// ATTACK STUB FOR T1
//─────────────────────────────────────────────────────────────────────────────
contract Attack_T1 {
    T1ConfigVuln public target;
    event AttackExecuted(T1AttackType attackType);

    constructor(T1ConfigVuln _t) { target = _t; }

    /// attacker “framing slip” by enabling Full without validation
    function framingSlip() external {
        target.enableLine(T1LineType.Full);
        emit AttackExecuted(T1AttackType.FramingSlip);
    }
}

//─────────────────────────────────────────────────────────────────────────────
// SAFE T1 CONFIGURATION (access‑controlled + defense logging)
//─────────────────────────────────────────────────────────────────────────────
contract T1ConfigSafe {
    mapping(T1LineType => bool) public enabled;
    address public admin;
    event T1Defense(T1DefenseType defenseType);
    error Unauthorized();

    constructor() {
        admin = msg.sender;
    }

    /// ✅ only admin may enable, and we emit which defense was applied
    function enableLine(T1LineType t) external {
        if (msg.sender != admin) revert Unauthorized();
        enabled[t] = true;
        emit T1Defense(T1DefenseType.FramingCheck);
    }
}


//─────────────────────────────────────────────────────────────────────────────
// TYPES FOR T3
//─────────────────────────────────────────────────────────────────────────────
/// T3 “line” variants (multiplex of 28 T1s)
enum T3LineType { DS3, M13, B3ZS }
/// Common attack vectors on T3
enum T3AttackType { DeMuxSlip, JitterInjection, Crosstalk }
/// Defense mechanisms for T3
enum T3DefenseType { DeMuxCheck, JitterBuffer, ErrorMonitoring }

//─────────────────────────────────────────────────────────────────────────────
// VULNERABLE T3 CONFIGURATION (no access control, no validation)
//─────────────────────────────────────────────────────────────────────────────
contract T3ConfigVuln {
    mapping(T3LineType => bool) public enabled;
    event T3Attack(T3AttackType attackType);

    /// ❌ unrestricted: log a generic attack event on any change
    function enableLine(T3LineType t) external {
        enabled[t] = true;
        emit T3Attack(T3AttackType.Crosstalk);
    }
}

//─────────────────────────────────────────────────────────────────────────────
// ATTACK STUB FOR T3
//─────────────────────────────────────────────────────────────────────────────
contract Attack_T3 {
    T3ConfigVuln public target;
    event AttackExecuted(T3AttackType attackType);

    constructor(T3ConfigVuln _t) { target = _t; }

    /// attacker injects jitter by enabling DS3 line with no checks
    function jitterInject() external {
        target.enableLine(T3LineType.DS3);
        emit AttackExecuted(T3AttackType.JitterInjection);
    }
}

//─────────────────────────────────────────────────────────────────────────────
// SAFE T3 CONFIGURATION (access‑controlled + defense logging)
//─────────────────────────────────────────────────────────────────────────────
contract T3ConfigSafe {
    mapping(T3LineType => bool) public enabled;
    address public admin;
    event T3Defense(T3DefenseType defenseType);
    error Unauthorized();

    constructor() {
        admin = msg.sender;
    }

    /// ✅ only admin may enable, and emit the defense applied
    function enableLine(T3LineType t) external {
        if (msg.sender != admin) revert Unauthorized();
        enabled[t] = true;
        emit T3Defense(T3DefenseType.JitterBuffer);
    }
}
