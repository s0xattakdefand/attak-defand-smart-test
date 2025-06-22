// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SystemSecurityOfficerSuite.sol
/// @notice On‑chain analogues of four “System Security Officer” patterns:
///   1) Officer Role Assignment  
///   2) Privileged Operation  
///   3) Audit Trail  
///   4) Emergency Pause  

error SSO__Unauthorized();
error SSO__Paused();

////////////////////////////////////////////////////////////////////////
// 1) OFFICER ROLE ASSIGNMENT
//    • Type: appoint a system security officer  
//    • Attack: anyone can reappoint themselves  
//    • Defense: only current officer may appoint a successor  
////////////////////////////////////////////////////////////////////////

contract OfficerRoleVuln {
    address public officer;

    constructor() { officer = msg.sender; }

    /// ❌ no access control
    function setOfficer(address newOfficer) external {
        officer = newOfficer;
    }
}

contract Attack_OfficerRole {
    OfficerRoleVuln public target;

    constructor(OfficerRoleVuln _t) { target = _t; }

    function hijack() external {
        // attacker reappoints themselves
        target.setOfficer(msg.sender);
    }
}

contract OfficerRoleSafe {
    address public officer;
    event OfficerChanged(address indexed oldOfficer, address indexed newOfficer);

    constructor() { officer = msg.sender; }

    /// ✅ only current officer may appoint
    function setOfficer(address newOfficer) external {
        if (msg.sender != officer) revert SSO__Unauthorized();
        emit OfficerChanged(officer, newOfficer);
        officer = newOfficer;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) PRIVILEGED OPERATION
//    • Type: a sensitive admin action  
//    • Attack: anyone invokes it  
//    • Defense: restrict to officer  
////////////////////////////////////////////////////////////////////////

contract SensitiveActionVuln {
    uint public criticalValue;

    /// ❌ no officer check
    function sensitiveOperation(uint v) external {
        criticalValue = v;
    }
}

contract Attack_SensitiveOperation {
    SensitiveActionVuln public target;

    constructor(SensitiveActionVuln _t) { target = _t; }

    function exploit(uint v) external {
        // attacker runs it at will
        target.sensitiveOperation(v);
    }
}

contract SensitiveActionSafe is OfficerRoleSafe {
    uint public criticalValue;
    event SensitiveOperation(address indexed by, uint value);

    /// ✅ only officer may run
    function sensitiveOperation(uint v) external {
        if (msg.sender != officer) revert SSO__Unauthorized();
        criticalValue = v;
        emit SensitiveOperation(msg.sender, v);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) AUDIT TRAIL
//    • Type: record security‑relevant events  
//    • Attack: no logs → off‑chain cannot detect  
//    • Defense: emit structured events with officer/timestamp  
////////////////////////////////////////////////////////////////////////

contract AuditTrailVuln {
    uint public x;

    /// ❌ no logging
    function update(uint v) external {
        x = v;
    }
}

contract Attack_AuditTrail {
    AuditTrailVuln public target;

    constructor(AuditTrailVuln _t) { target = _t; }

    function doIt(uint v) external {
        target.update(v);
    }
}

contract AuditTrailSafe is OfficerRoleSafe {
    uint public x;
    event UpdateLogged(address indexed by, uint oldValue, uint newValue, uint timestamp);

    /// ✅ only officer + rich event
    function update(uint v) external {
        if (msg.sender != officer) revert SSO__Unauthorized();
        uint old = x;
        x = v;
        emit UpdateLogged(msg.sender, old, v, block.timestamp);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) EMERGENCY PAUSE
//    • Type: globally halt operations  
//    • Attack: no pause → no response to incidents  
//    • Defense: officer may pause/unpause with guard  
////////////////////////////////////////////////////////////////////////

contract PauseFunctionVuln {
    bool public paused;

    /// ❌ anyone can toggle
    function setPaused(bool p) external {
        paused = p;
    }

    function operate() external view returns (string memory) {
        require(!paused, "paused");
        return "operating";
    }
}

contract Attack_PauseFunction {
    PauseFunctionVuln public target;

    constructor(PauseFunctionVuln _t) { target = _t; }

    function hijack() external {
        target.setPaused(true);
    }
}

contract PauseFunctionSafe is OfficerRoleSafe {
    bool public paused;
    event Paused(address indexed by);
    event Unpaused(address indexed by);

    /// ✅ only officer + events
    function setPaused(bool p) external {
        if (msg.sender != officer) revert SSO__Unauthorized();
        paused = p;
        if (p) emit Paused(msg.sender);
        else emit Unpaused(msg.sender);
    }

    function operate() external view returns (string memory) {
        if (paused) revert SSO__Paused();
        return "operating";
    }
}
