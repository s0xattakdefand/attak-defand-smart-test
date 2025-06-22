// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SwitchSuite.sol
/// @notice On‑chain analogues of four “switch” (layer‑2 network switch) patterns:
///   1) Port/VLAN Configuration  
///   2) MAC‑Table Learning & Flooding  
///   3) VLAN‑Hopping via Untagged Frames  
///   4) STP (Spanning Tree) Root Bridge Election  

error Switch__NotAdmin();
error Switch__MacTableFull();
error Switch__VlanAccessDenied();
error Switch__StpNotAllowed();

////////////////////////////////////////////////////////////////////////////////
// 1) PORT/VLAN CONFIGURATION
//
//   • Vulnerable: anyone can assign ports to VLANs.
//   • Attack: hijack a victim’s port into sensitive VLAN.
//   • Defense: only admin may assign ports.
////////////////////////////////////////////////////////////////////////////////
contract PortVlanVuln {
    mapping(uint16 => address[]) public vlanMembers;

    function addPortToVlan(uint16 vlan, address port) external {
        // ❌ unrestricted
        vlanMembers[vlan].push(port);
    }
}

contract Attack_PortVlan {
    PortVlanVuln public sw;
    constructor(PortVlanVuln _sw) { sw = _sw; }
    function hijackPort(address victimPort) external {
        // attacker moves victim’s port into VLAN 999
        sw.addPortToVlan(999, victimPort);
    }
}

contract PortVlanSafe {
    mapping(uint16 => address[]) private vlanMembers;
    address public admin;
    event PortAssigned(uint16 indexed vlan, address port);

    constructor() { admin = msg.sender; }

    function addPortToVlan(uint16 vlan, address port) external {
        if (msg.sender != admin) revert Switch__NotAdmin();
        vlanMembers[vlan].push(port);
        emit PortAssigned(vlan, port);
    }

    function getVlanMembers(uint16 vlan) external view returns (address[] memory) {
        return vlanMembers[vlan];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) MAC‑TABLE LEARNING & FLOODING
//
//   • Vulnerable: unlimited MAC entries → attacker floods table.
//   • Attack: learn thousands of fake MACs to overflow.
//   • Defense: cap per‑port MAC table size.
////////////////////////////////////////////////////////////////////////////////
contract MacTableVuln {
    // port => mac => learned
    mapping(address => mapping(address => bool)) public macTable;

    function learn(address port, address mac) external {
        // ❌ no limit
        macTable[port][mac] = true;
    }
}

contract Attack_MacFlood {
    MacTableVuln public sw;
    constructor(MacTableVuln _sw) { sw = _sw; }
    function floodMacs(address port, address[] calldata macs) external {
        for (uint i = 0; i < macs.length; i++) {
            sw.learn(port, macs[i]);
        }
    }
}

contract MacTableSafe {
    mapping(address => address[]) public macEntries;
    mapping(address => mapping(address => bool)) public macTable;
    uint256 public constant MAX_PER_PORT = 100;

    function learn(address port, address mac) external {
        address[] storage entries = macEntries[port];
        if (entries.length >= MAX_PER_PORT) revert Switch__MacTableFull();
        if (!macTable[port][mac]) {
            entries.push(mac);
            macTable[port][mac] = true;
        }
    }

    function getMacs(address port) external view returns (address[] memory) {
        return macEntries[port];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) VLAN‑HOPPING VIA UNTAGGED FRAMES
//
//   • Vulnerable: untagged ingress frames accepted on any VLAN.
//   • Attack: send untagged frame → falls into native VLAN 1 on trunk.
//   • Defense: enforce explicit VLAN tagging or drop mismatched VLAN.
////////////////////////////////////////////////////////////////////////////////
contract VlanHopVuln {
    mapping(address => uint16) public portNativeVlan;

    function setNativeVlan(address port, uint16 vlan) external {
        portNativeVlan[port] = vlan;
    }

    /// sendFrame: no VLAN tag check
    function sendFrame(address ingressPort, uint16 tagVlan, bytes calldata payload) external pure returns (bool) {
        // ❌ if tagVlan == 0 (untagged), frame goes to native VLAN without check
        // ... frame forwarded ...
        return true;
    }
}

contract Attack_VlanHop {
    VlanHopVuln public sw;
    constructor(VlanHopVuln _sw) { sw = _sw; }
    function sendUntTagged(address ingressPort) external view returns (bool) {
        // tagVlan = 0 means untagged
        return sw.sendFrame(ingressPort, 0, "");
    }
}

contract VlanHopSafe {
    mapping(address => uint16) public portNativeVlan;
    address public admin;
    error Switch__VlanAccessDenied();

    constructor() { admin = msg.sender; }

    function setNativeVlan(address port, uint16 vlan) external {
        if (msg.sender != admin) revert Switch__NotAdmin();
        portNativeVlan[port] = vlan;
    }

    /// sendFrame: drop untagged frames that don't match native VLAN
    function sendFrame(address ingressPort, uint16 tagVlan, bytes calldata payload) external view returns (bool) {
        if (tagVlan == 0) {
            // untagged must match native VLAN
            tagVlan = portNativeVlan[ingressPort];
            if (tagVlan == 0) revert Switch__VlanAccessDenied();
        }
        // ... forward on tagVlan ...
        return true;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) STP ROOT BRIDGE ELECTION
//
//   • Vulnerable: any bridge can become root → hijack spanning tree.
//   • Attack: send malicious BPDU to become root.
//   • Defense: whitelist only authorized bridges.
////////////////////////////////////////////////////////////////////////////////
contract StpVuln {
    address public rootBridge;

    function sendBpdu(address bridge, uint64 priority) external {
        // ❌ no guard: lower priority → becomes root
        rootBridge = bridge;
    }
}

contract Attack_StpHijack {
    StpVuln public sw;
    constructor(StpVuln _sw) { sw = _sw; }
    function claimRoot() external {
        // maliciously claim as root
        sw.sendBpdu(msg.sender, 0);
    }
}

contract StpSafe {
    mapping(address => bool) public authorized;
    address public admin;
    event RootChanged(address indexed old, address indexed newRoot);

    constructor(address[] memory initial) {
        admin = msg.sender;
        for (uint i = 0; i < initial.length; i++) {
            authorized[initial[i]] = true;
        }
    }

    function authorizeBridge(address bridge, bool ok) external {
        if (msg.sender != admin) revert Switch__NotAdmin();
        authorized[bridge] = ok;
    }

    function sendBpdu(address bridge, uint64 priority) external {
        if (!authorized[bridge]) revert Switch__StpNotAllowed();
        emit RootChanged(rootBridge, bridge);
        rootBridge = bridge;
    }

    address public rootBridge;
}
