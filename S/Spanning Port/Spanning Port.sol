// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SpanningPortSuite.sol
/// @notice On‑chain analogues of four “Spanning Port” patterns:
///   1) Unrestricted Mirror Configuration  
///   2) Mirror Config Flood (DoS)  
///   3) Traffic Mirror Loop  
///   4) Sensitive Traffic Logging  

error SP__NotAdmin();
error SP__RateLimit();
error SP__LoopDetected();
error SP__NotAllowed();

interface IDataConsumer {
    function receiveData(bytes calldata data) external;
}

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED MIRROR CONFIGURATION
//
//   • Vulnerable: anyone can configure the mirror port
//   • Attack: set mirror to attacker’s port
//   • Defense: restrict to admin
////////////////////////////////////////////////////////////////////////
contract SpanPortVuln {
    address public mirrorPort;
    event MirrorSet(address indexed who, address indexed port);

    function setMirrorPort(address port) external {
        // ❌ no access control
        mirrorPort = port;
        emit MirrorSet(msg.sender, port);
    }

    function forward(bytes calldata data) external {
        IDataConsumer(mirrorPort).receiveData(data);
    }
}

contract Attack_SpanPortConfig {
    SpanPortVuln public sw;
    constructor(SpanPortVuln _sw) { sw = _sw; }
    function hijack(address evilPort) external {
        sw.setMirrorPort(evilPort);
    }
}

contract SpanPortSafe {
    address public admin;
    address public mirrorPort;
    event MirrorSet(address indexed by, address indexed port);

    constructor() { admin = msg.sender; }

    function setMirrorPort(address port) public virtual {
        if (msg.sender != admin) revert SP__NotAdmin();
        mirrorPort = port;
        emit MirrorSet(msg.sender, port);
    }

    function forward(bytes calldata data) external {
        IDataConsumer(mirrorPort).receiveData(data);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) MIRROR CONFIG FLOOD (DoS)
//
//   • Vulnerable: unlimited reconfiguration events
//   • Attack: flood setMirrorPort calls
//   • Defense: rate‑limit per block
////////////////////////////////////////////////////////////////////////
contract SpanFloodVuln is SpanPortSafe {
    // inherits unrestricted behavior
}

contract Attack_SpanFlood {
    SpanFloodVuln public sw;
    constructor(SpanFloodVuln _sw) { sw = _sw; }
    function flood(address port, uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            sw.setMirrorPort(port);
        }
    }
}

contract SpanFloodSafe is SpanPortSafe {
    mapping(uint256 => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 2;

    function setMirrorPort(address port) public override {
        if (msg.sender != admin) revert SP__NotAdmin();
        uint256 b = block.number;
        countInBlock[b]++;
        if (countInBlock[b] > MAX_PER_BLOCK) revert SP__RateLimit();
        mirrorPort = port;
        emit MirrorSet(msg.sender, port);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) TRAFFIC MIRROR LOOP
//
//   • Vulnerable: mirror A→B and B→A indefinitely
//   • Attack: set two ports to mirror each other, causing infinite loop
//   • Defense: prevent loops by disallowing A==B
////////////////////////////////////////////////////////////////////////
contract LoopSpanVuln {
    address public portA;
    address public portB;

    function setPorts(address a, address b) external {
        portA = a;
        portB = b;
    }

    function mirrorToB(bytes calldata data) external {
        IDataConsumer(portB).receiveData(data);
    }
    function mirrorToA(bytes calldata data) external {
        IDataConsumer(portA).receiveData(data);
    }
}

contract Attack_LoopSpan {
    LoopSpanVuln public sw;
    constructor(LoopSpanVuln _sw) { sw = _sw; }
    function createLoop(address a, address b) external {
        sw.setPorts(a, b);
    }
    // Off-chain repetition of mirrorToB and mirrorToA loops until gas exhaustion
}

contract LoopSpanSafe {
    address public portA;
    address public portB;
    address public admin;
    event PortsSet(address indexed a, address indexed b);

    constructor() { admin = msg.sender; }

    function setPorts(address a, address b) external {
        if (msg.sender != admin) revert SP__NotAdmin();
        if (a == b) revert SP__LoopDetected();
        portA = a;
        portB = b;
        emit PortsSet(a, b);
    }

    function mirrorToB(bytes calldata data) external {
        IDataConsumer(portB).receiveData(data);
    }
    function mirrorToA(bytes calldata data) external {
        IDataConsumer(portA).receiveData(data);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SENSITIVE TRAFFIC LOGGING
//
//   • Vulnerable: logs raw mirrored data
//   • Attack: off‑chain observer reads events
//   • Defense: emit only hashes
////////////////////////////////////////////////////////////////////////
contract SpanLogVuln {
    event Mirrored(address indexed mirrorPort, bytes data);
    address public mirrorPort;

    function setMirrorPort(address port) external {
        mirrorPort = port;
    }

    function forward(bytes calldata data) external {
        emit Mirrored(mirrorPort, data);
        IDataConsumer(mirrorPort).receiveData(data);
    }
}

contract SpanLogSafe {
    event MirroredHash(address indexed mirrorPort, bytes32 dataHash);
    address public admin;
    address public mirrorPort;

    constructor() { admin = msg.sender; }

    function setMirrorPort(address port) external {
        if (msg.sender != admin) revert SP__NotAllowed();
        mirrorPort = port;
    }

    function forward(bytes calldata data) external {
        emit MirroredHash(mirrorPort, keccak256(data));
        IDataConsumer(mirrorPort).receiveData(data);
    }
}
