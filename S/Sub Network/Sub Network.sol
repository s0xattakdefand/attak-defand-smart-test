// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SubNetworkSuite.sol
/// @notice Four on‑chain “Sub‑Network” patterns with vulnerabilities and hardened defenses:
///   1) Unrestricted Membership Registration  
///   2) Broadcast Flooding (DoS)  
///   3) Unauthorized Cross‑Network Broadcast  
///   4) Recursive Network Resolution (Cycle Detection)  

error SN__NotOwner();
error SN__TooManyMessages();
error SN__NotMember();
error SN__LoopDetected();

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED MEMBERSHIP REGISTRATION
//
//  • Vulnerable: anyone can add any user to any network
//  • Attack: hijack a victim’s network membership
//  • Defense: only owner may add members
////////////////////////////////////////////////////////////////////////
contract SubNetworkRegistryVuln {
    mapping(uint16 => address[]) public members;
    function addMember(uint16 netId, address user) external {
        // ❌ no access control
        members[netId].push(user);
    }
}

contract Attack_SubNetworkHijack {
    SubNetworkRegistryVuln public reg;
    constructor(SubNetworkRegistryVuln _r) { reg = _r; }
    function hijack(uint16 netId) external {
        // attacker adds themselves to any network
        reg.addMember(netId, msg.sender);
    }
}

contract SubNetworkRegistrySafe {
    mapping(uint16 => address[]) private members;
    mapping(uint16 => mapping(address => bool)) public isMember;
    address public immutable owner;
    event MemberAdded(uint16 indexed netId, address indexed user);

    constructor() { owner = msg.sender; }

    function addMember(uint16 netId, address user) external {
        if (msg.sender != owner) revert SN__NotOwner();
        if (!isMember[netId][user]) {
            members[netId].push(user);
            isMember[netId][user] = true;
            emit MemberAdded(netId, user);
        }
    }

    function getMembers(uint16 netId) external view returns (address[] memory) {
        return members[netId];
    }
}

////////////////////////////////////////////////////////////////////////
// 2) BROADCAST FLOODING (DoS)
//
//  • Vulnerable: unlimited messages per network
//  • Attack: flood a network with messages, exhausting gas/storage
//  • Defense: rate‑limit per sender per network
////////////////////////////////////////////////////////////////////////
contract SubNetworkBroadcastVuln {
    mapping(uint16 => bytes[]) public messages;
    function broadcast(uint16 netId, bytes calldata data) external {
        // ❌ no rate-limit
        messages[netId].push(data);
    }
}

contract Attack_BroadcastFlood {
    SubNetworkBroadcastVuln public b;
    constructor(SubNetworkBroadcastVuln _b) { b = _b; }
    function flood(uint16 netId, bytes calldata data, uint n) external {
        for (uint i; i < n; i++) {
            b.broadcast(netId, data);
        }
    }
}

contract SubNetworkBroadcastSafe {
    mapping(uint16 => bytes[]) public messages;
    mapping(uint16 => mapping(address => uint)) public count;
    uint public constant MAX_PER_BLOCK = 5;
    event Broadcast(uint16 indexed netId, address indexed sender, bytes data);

    function broadcast(uint16 netId, bytes calldata data) external {
        if (count[netId][msg.sender] >= MAX_PER_BLOCK) revert SN__TooManyMessages();
        count[netId][msg.sender]++;
        messages[netId].push(data);
        emit Broadcast(netId, msg.sender, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) UNAUTHORIZED CROSS‑NETWORK BROADCAST
//
//  • Vulnerable: no membership check on broadcast
//  • Attack: non‑members can send into any network
//  • Defense: require membership
////////////////////////////////////////////////////////////////////////
contract SubNetworkCrossVuln {
    mapping(uint16 => address[]) public members;
    mapping(uint16 => bytes[])  public messages;

    function broadcast(uint16 netId, bytes calldata data) external {
        // ❌ anyone can broadcast
        messages[netId].push(data);
    }
}

contract Attack_CrossNetwork {
    SubNetworkCrossVuln public c;
    constructor(SubNetworkCrossVuln _c) { c = _c; }
    function leak(uint16 netId, bytes calldata data) external {
        // non‑member can broadcast
        c.broadcast(netId, data);
    }
}

contract SubNetworkCrossSafe {
    mapping(uint16 => address[]) public members;
    mapping(uint16 => mapping(address => bool)) public isMember;
    mapping(uint16 => bytes[]) public messages;
    event Broadcast(uint16 indexed netId, address indexed sender, bytes data);

    function addMember(uint16 netId, address user) external {
        // for demo, open; in practice restrict to admin
        members[netId].push(user);
        isMember[netId][user] = true;
    }

    function broadcast(uint16 netId, bytes calldata data) external {
        if (!isMember[netId][msg.sender]) revert SN__NotMember();
        messages[netId].push(data);
        emit Broadcast(netId, msg.sender, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) RECURSIVE NETWORK RESOLUTION (CYCLE DETECTION)
//
//  • Vulnerable: resolve parent chain with no cycle check → infinite loop
//  • Attack: create cycle a→b, b→a then call resolve(a)
//  • Defense: detect loops via depth limit
////////////////////////////////////////////////////////////////////////
contract SubNetworkParentVuln {
    mapping(uint16 => uint16) public parentOf;

    function setParent(uint16 netId, uint16 parentId) external {
        parentOf[netId] = parentId;
    }

    function resolve(uint16 netId) external view returns (uint16) {
        uint16 cur = netId;
        // ❌ never exits on a cycle
        while (parentOf[cur] != 0) {
            cur = parentOf[cur];
        }
        return cur;
    }
}

contract Attack_ResolveLoop {
    SubNetworkParentVuln public p;
    constructor(SubNetworkParentVuln _p) { p = _p; }
    function exploit(uint16 a, uint16 b) external {
        p.setParent(a, b);
        p.setParent(b, a);
    }
    function test(uint16 a) external view {
        p.resolve(a); // would loop infinitely
    }
}

contract SubNetworkParentSafe {
    mapping(uint16 => uint16) public parentOf;
    uint8 public constant MAX_DEPTH = 10;

    error SN__LoopDetected();

    function setParent(uint16 netId, uint16 parentId) external {
        parentOf[netId] = parentId;
    }

    function resolve(uint16 netId) external view returns (uint16) {
        uint16 cur = netId;
        for (uint8 i = 0; i < MAX_DEPTH; i++) {
            uint16 next = parentOf[cur];
            if (next == 0) return cur;
            cur = next;
        }
        revert SN__LoopDetected();
    }
}
