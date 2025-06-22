// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TrunkingSuite.sol
/// @notice On‑chain analogues of “Trunking” patterns in network switches:
///   Types: PortAccess, VLANTagging  
///   AttackTypes: Misconfig, VLANHopping, VLANFlood  
///   DefenseTypes: OwnerAuth, VLANWhitelist, RateLimit  

enum TrunkingType         { PortAccess, VLANTagging }
enum TrunkingAttackType   { Misconfig, VLANHopping, VLANFlood }
enum TrunkingDefenseType  { OwnerAuth, VLANWhitelist, RateLimit }

error TK__NotOwner();
error TK__VLANForbidden();
error TK__TooManyChanges();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE TRUNK CONFIGURATION
///
///    • anyone may add or remove VLANs on any port  
///    • Attack: Misconfig or VLANHopping  
///─────────────────────────────────────────────────────────────────────────────
contract TrunkingVuln {
    // port → list of allowed VLANs
    mapping(uint16 => uint16[]) public trunks;
    event TrunkChanged(uint16 indexed port, uint16 vlan, bool added, TrunkingAttackType attack);

    function addVLAN(uint16 port, uint16 vlan) external {
        trunks[port].push(vlan);
        emit TrunkChanged(port, vlan, true, TrunkingAttackType.Misconfig);
    }

    function removeVLAN(uint16 port, uint16 vlan) external {
        // naive remove: may leave holes
        uint16[] storage vlans = trunks[port];
        for (uint i; i < vlans.length; i++) {
            if (vlans[i] == vlan) {
                vlans[i] = vlans[vlans.length - 1];
                vlans.pop();
                break;
            }
        }
        emit TrunkChanged(port, vlan, false, TrunkingAttackType.Misconfig);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • attacker configures unauthorized VLANs, hops into others’ traffic  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Trunking {
    TrunkingVuln public sw;
    constructor(TrunkingVuln _sw) { sw = _sw; }

    function hijackPort(uint16 port, uint16 unauthorizedVLAN) external {
        sw.addVLAN(port, unauthorizedVLAN);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE TRUNKING (OWNER ONLY)
///
///    • Defense: only the owner may change trunk configuration  
///─────────────────────────────────────────────────────────────────────────────
contract TrunkingSafe {
    mapping(uint16 => uint16[]) public trunks;
    address public owner;
    event TrunkChanged(uint16 indexed port, uint16 vlan, bool added, TrunkingDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function addVLAN(uint16 port, uint16 vlan) external {
        if (msg.sender != owner) revert TK__NotOwner();
        trunks[port].push(vlan);
        emit TrunkChanged(port, vlan, true, TrunkingDefenseType.OwnerAuth);
    }

    function removeVLAN(uint16 port, uint16 vlan) external {
        if (msg.sender != owner) revert TK__NotOwner();
        uint16[] storage vlans = trunks[port];
        for (uint i; i < vlans.length; i++) {
            if (vlans[i] == vlan) {
                vlans[i] = vlans[vlans.length - 1];
                vlans.pop();
                break;
            }
        }
        emit TrunkChanged(port, vlan, false, TrunkingDefenseType.OwnerAuth);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) VLAN‑WHITELISTED TRUNKING
///
///    • Defense: only allow VLANs from a predefined whitelist  
///─────────────────────────────────────────────────────────────────────────────
contract TrunkingSafeWhitelist {
    mapping(uint16 => uint16[]) public trunks;
    mapping(uint16 => bool)    public vlanAllowed;
    address public owner;
    event TrunkChanged(uint16 indexed port, uint16 vlan, bool added, TrunkingDefenseType defense);

    constructor(uint16[] memory allowedVLANs) {
        owner = msg.sender;
        for (uint i; i < allowedVLANs.length; i++) {
            vlanAllowed[allowedVLANs[i]] = true;
        }
    }

    function addAllowedVLAN(uint16 vlan, bool ok) external {
        if (msg.sender != owner) revert TK__NotOwner();
        vlanAllowed[vlan] = ok;
    }

    function addVLAN(uint16 port, uint16 vlan) external {
        if (msg.sender != owner)    revert TK__NotOwner();
        if (!vlanAllowed[vlan])     revert TK__VLANForbidden();
        trunks[port].push(vlan);
        emit TrunkChanged(port, vlan, true, TrunkingDefenseType.VLANWhitelist);
    }

    function removeVLAN(uint16 port, uint16 vlan) external {
        if (msg.sender != owner)    revert TK__NotOwner();
        uint16[] storage vlans = trunks[port];
        for (uint i; i < vlans.length; i++) {
            if (vlans[i] == vlan) {
                vlans[i] = vlans[vlans.length - 1];
                vlans.pop();
                break;
            }
        }
        emit TrunkChanged(port, vlan, false, TrunkingDefenseType.VLANWhitelist);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) RATE‑LIMITED TRUNK CHANGES
///
///    • Defense: cap number of trunk updates per block to prevent VLANFlood  
///─────────────────────────────────────────────────────────────────────────────
contract TrunkingSafeRateLimit {
    mapping(uint16 => uint16[]) public trunks;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public changesInBlock;
    uint256 public constant MAX_CHANGES_PER_BLOCK = 5;
    address public owner;
    event TrunkChanged(uint16 indexed port, uint16 vlan, bool added, TrunkingDefenseType defense);

    constructor() {
        owner = msg.sender;
    }

    function _rateLimit() internal {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            changesInBlock[msg.sender] = 0;
        }
        changesInBlock[msg.sender]++;
        if (changesInBlock[msg.sender] > MAX_CHANGES_PER_BLOCK) revert TK__TooManyChanges();
    }

    function addVLAN(uint16 port, uint16 vlan) external {
        if (msg.sender != owner) revert TK__NotOwner();
        _rateLimit();
        trunks[port].push(vlan);
        emit TrunkChanged(port, vlan, true, TrunkingDefenseType.RateLimit);
    }

    function removeVLAN(uint16 port, uint16 vlan) external {
        if (msg.sender != owner) revert TK__NotOwner();
        _rateLimit();
        uint16[] storage vlans = trunks[port];
        for (uint i; i < vlans.length; i++) {
            if (vlans[i] == vlan) {
                vlans[i] = vlans[vlans.length - 1];
                vlans.pop();
                break;
            }
        }
        emit TrunkChanged(port, vlan, false, TrunkingDefenseType.RateLimit);
    }
}
