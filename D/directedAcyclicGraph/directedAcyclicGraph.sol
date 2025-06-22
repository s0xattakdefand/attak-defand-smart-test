// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DirectedAcyclicGraphSuite.sol
/// @notice On‐chain analogues of “Directed Acyclic Graph” (DAG) patterns:
///   Types: StaticDAG, DynamicDAG, PartitionedDAG, VersionedDAG  
///   AttackTypes: CycleInjection, EdgeTampering, NodeSpam, Replay  
///   DefenseTypes: AccessControl, CycleCheck, RateLimit, SignatureValidation, AuditLogging

enum DAGType              { StaticDAG, DynamicDAG, PartitionedDAG, VersionedDAG }
enum DAGAttackType        { CycleInjection, EdgeTampering, NodeSpam, Replay }
enum DAGDefenseType       { AccessControl, CycleCheck, RateLimit, SignatureValidation, AuditLogging }

error DAG__NotAuthorized();
error DAG__CycleDetected();
error DAG__TooManyRequests();
error DAG__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DAG MANAGER
//    • ❌ no checks: cycles and tampering possible → CycleInjection, EdgeTampering
////////////////////////////////////////////////////////////////////////////////
contract DAGVuln {
    // adjacency list: node => children
    mapping(uint256 => uint256[]) public children;

    event EdgeAdded(
        address indexed who,
        uint256           from,
        uint256           to,
        DAGType           dtype,
        DAGAttackType     attack
    );

    function addEdge(uint256 from, uint256 to, DAGType dtype) external {
        children[from].push(to);
        emit EdgeAdded(msg.sender, from, to, dtype, DAGAttackType.EdgeTampering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates cycle injection, node spam, replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_DAG {
    DAGVuln public target;
    uint256 public lastFrom;
    uint256 public lastTo;
    DAGType public lastType;

    constructor(DAGVuln _t) {
        target = _t;
    }

    function injectCycle(uint256 a, uint256 b) external {
        target.addEdge(a, b, DAGType.DynamicDAG);
        target.addEdge(b, a, DAGType.DynamicDAG);
        lastFrom = a;
        lastTo   = b;
        lastType = DAGType.DynamicDAG;
    }

    function spamNodes(uint256 base, uint count) external {
        for (uint i = 0; i < count; i++) {
            target.addEdge(base, base + i + 1, DAGType.PartitionedDAG);
        }
    }

    function replay() external {
        target.addEdge(lastFrom, lastTo, lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may add edges
////////////////////////////////////////////////////////////////////////////////
contract DAGSafeAccess {
    mapping(uint256 => uint256[]) public children;
    address public owner;

    event EdgeAdded(
        address indexed who,
        uint256           from,
        uint256           to,
        DAGType           dtype,
        DAGDefenseType    defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DAG__NotAuthorized();
        _;
    }

    function addEdge(uint256 from, uint256 to, DAGType dtype) external onlyOwner {
        children[from].push(to);
        emit EdgeAdded(msg.sender, from, to, dtype, DAGDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH CYCLE CHECK & RATE LIMIT
//    • ✅ Defense: CycleCheck – perform DFS to prevent cycles  
//               RateLimit  – cap adds per block
////////////////////////////////////////////////////////////////////////////////
contract DAGSafeValidate {
    mapping(uint256 => uint256[]) public children;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event EdgeAdded(
        address indexed who,
        uint256           from,
        uint256           to,
        DAGType           dtype,
        DAGDefenseType    defense
    );

    error DAG__TooManyRequests();

    function _detectCycle(uint256 start, uint256 target) internal view returns (bool) {
        // simple DFS stack (gas‐heavy stub)
        uint256;
        bool;
        uint sp = 0;
        stack[sp++] = target;
        while (sp > 0) {
            uint256 u = stack[--sp];
            if (u == start) return true;
            if (seen[u]) continue;
            seen[u] = true;
            uint256[] storage kids = children[u];
            for (uint i; i < kids.length; i++) {
                stack[sp++] = kids[i];
            }
        }
        return false;
    }

    function addEdge(uint256 from, uint256 to, DAGType dtype) external {
        // rate‐limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert DAG__TooManyRequests();

        // cycle prevention
        if (_detectCycle(from, to)) revert DAG__CycleDetected();

        children[from].push(to);
        emit EdgeAdded(msg.sender, from, to, dtype, DAGDefenseType.CycleCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed params  
//               AuditLogging      – record each addition
////////////////////////////////////////////////////////////////////////////////
contract DAGSafeAdvanced {
    mapping(uint256 => uint256[]) public children;
    address public signer;

    event EdgeAdded(
        address indexed who,
        uint256           from,
        uint256           to,
        DAGType           dtype,
        DAGDefenseType    defense
    );
    event AuditLog(
        address indexed who,
        uint256           from,
        uint256           to,
        DAGType           dtype,
        DAGDefenseType    defense
    );

    error DAG__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function addEdge(
        uint256 from,
        uint256 to,
        DAGType dtype,
        bytes calldata sig
    ) external {
        // verify signature over (from||to||dtype)
        bytes32 h = keccak256(abi.encodePacked(from, to, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DAG__InvalidSignature();

        children[from].push(to);
        emit EdgeAdded(msg.sender, from, to, dtype, DAGDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, from, to, dtype, DAGDefenseType.AuditLogging);
    }
}
