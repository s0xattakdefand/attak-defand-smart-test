// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TamperSuite.sol
/// @notice On‑chain analogues of common “Tamper” patterns:
///   • Types: DataTamper, LogTamper, ConfigTamper  
///   • Attack types: OverwriteData, AlterLog, ReplayConfig  
///   • Defense types: AccessControl, ImmutableStorage, AuditLogging  

enum TamperType         { DataTamper, LogTamper, ConfigTamper }
enum TamperAttackType   { OverwriteData, AlterLog, ReplayConfig }
enum TamperDefenseType  { AccessControl, ImmutableStorage, AuditLogging }

error TPR__Unauthorized();
error TPR__AlreadySet();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATA STORE (no controls, no logging)
//    • Type: DataTamper
//    • Attack: OverwriteData
//    • Defense: — 
////////////////////////////////////////////////////////////////////////
contract TamperVuln {
    mapping(uint256 => string) public dataStore;

    /// ❌ anyone can overwrite any entry at will
    function setData(uint256 id, string calldata value) external {
        dataStore[id] = value;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • OverwriteData
////////////////////////////////////////////////////////////////////////
contract Attack_Tamper {
    TamperVuln public target;
    constructor(TamperVuln _t) { target = _t; }

    /// attacker force‑writes malicious payload
    function overwrite(uint256 id, string calldata evil) external {
        target.setData(id, evil);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE DATA STORE (owner‑controlled, write‑once, audit logging)
//    • Type: DataTamper
//    • Defense: AccessControl, ImmutableStorage, AuditLogging
////////////////////////////////////////////////////////////////////////
contract TamperSafe {
    address public owner;
    mapping(uint256 => string) private _data;
    mapping(uint256 => bool)   private _set;
    event DataRecorded(address indexed by, uint256 indexed id, string value, TamperDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    /// ✅ only owner may set, and only once per id
    function setData(uint256 id, string calldata value) external {
        if (msg.sender != owner) revert TPR__Unauthorized();
        if (_set[id])             revert TPR__AlreadySet();
        _set[id] = true;
        _data[id] = value;
        emit DataRecorded(msg.sender, id, value, TamperDefenseType.AccessControl);
        emit DataRecorded(msg.sender, id, value, TamperDefenseType.ImmutableStorage);
        emit DataRecorded(msg.sender, id, value, TamperDefenseType.AuditLogging);
    }

    function getData(uint256 id) external view returns (string memory) {
        return _data[id];
    }
}
