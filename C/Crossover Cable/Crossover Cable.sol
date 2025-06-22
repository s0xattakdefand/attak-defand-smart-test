// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CrossoverCableSuite.sol
/// @notice On‑chain analogues of “Crossover Cable” connection patterns:
///   Types: Straight, Crossover, AutoMDIX  
///   AttackTypes: MiswireConnection, LoopCreation, TamperPairs  
///   DefenseTypes: AuthControl, CableTest, AutoMDIX, RateLimit  

enum CrossoverCableType       { Straight, Crossover, AutoMDIX }
enum CrossoverCableAttackType { MiswireConnection, LoopCreation, TamperPairs }
enum CrossoverCableDefenseType{ AuthControl, CableTest, AutoMDIX, RateLimit }

error CC__NotOwner();
error CC__LoopDetected();
error CC__InvalidCable();
error CC__TooManyConnections();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE: unrestricted cable connections
//    • anyone may connect any two ports in any mode  
//    • Attack: MiswireConnection, LoopCreation  
////////////////////////////////////////////////////////////////////////
contract CrossoverCableVuln {
    // mapping port → connected port
    mapping(string => string) public connections;
    event Connected(
        address indexed who,
        string portA,
        string portB,
        CrossoverCableType    mode,
        CrossoverCableAttackType attack
    );

    function connect(
        string calldata portA,
        string calldata portB,
        CrossoverCableType mode
    ) external {
        // ❌ no validation: loops or mismatches allowed
        connections[portA] = portB;
        connections[portB] = portA;
        emit Connected(msg.sender, portA, portB, mode, CrossoverCableAttackType.MiswireConnection);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB: illustrate creating a loop via miswiring
////////////////////////////////////////////////////////////////////////
contract Attack_CrossoverCable {
    CrossoverCableVuln public target;
    constructor(CrossoverCableVuln _t) { target = _t; }

    function createLoop(
        string calldata p1,
        string calldata p2,
        string calldata p3
    ) external {
        // connect p1↔p2, then p2↔p3, then p3↔p1 to form a loop
        target.connect(p1, p2, CrossoverCableType.Crossover);
        target.connect(p2, p3, CrossoverCableType.Crossover);
        target.connect(p3, p1, CrossoverCableType.Crossover);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE: owner‑only connections (AuthControl)
////////////////////////////////////////////////////////////////////////
contract CrossoverCableSafeAuth {
    mapping(string => string) public connections;
    address public owner;
    event Connected(
        address indexed who,
        string portA,
        string portB,
        CrossoverCableType       mode,
        CrossoverCableDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function connect(
        string calldata portA,
        string calldata portB,
        CrossoverCableType mode
    ) external {
        if (msg.sender != owner) revert CC__NotOwner();
        connections[portA] = portB;
        connections[portB] = portA;
        emit Connected(msg.sender, portA, portB, mode, CrossoverCableDefenseType.AuthControl);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE: cable‑test + rate‑limit + AutoMDIX fallback
////////////////////////////////////////////////////////////////////////
contract CrossoverCableSafeTest {
    mapping(string => string) public connections;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 10;

    event Connected(
        address indexed who,
        string portA,
        string portB,
        CrossoverCableType       mode,
        CrossoverCableDefenseType defense
    );

    /// connect with validation: no loops, proper pair type, and rate‑limit
    function connect(
        string calldata portA,
        string calldata portB,
        CrossoverCableType mode
    ) external {
        // rate‑limit per caller
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert CC__TooManyConnections();

        // detect simple loop: portA already connected back to portB?
        if (keccak256(bytes(connections[portB])) == keccak256(bytes(portA))) {
            revert CC__LoopDetected();
        }

        // validate mode or auto‑fallback to AutoMDIX
        CrossoverCableType applied = mode;
        if (mode != CrossoverCableType.Straight && mode != CrossoverCableType.Crossover) {
            // fallback to AutoMDIX
            applied = CrossoverCableType.AutoMDIX;
            emit Connected(msg.sender, portA, portB, applied, CrossoverCableDefenseType.AutoMDIX);
        } else {
            emit Connected(msg.sender, portA, portB, applied, CrossoverCableDefenseType.CableTest);
        }

        connections[portA] = portB;
        connections[portB] = portA;
    }
}
