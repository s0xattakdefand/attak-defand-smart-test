// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebAssemblySuite.sol
/// @notice On‐chain analogues of “WebAssembly” execution patterns:
///   Types: Native, Sandboxed, Standalone, Embedded  
///   AttackTypes: CodeInjection, MemoryCorruption, SideChannel, DenialOfService  
///   DefenseTypes: Sandboxing, Validation, RateLimit, ContinuousMonitoring  

enum WebAssemblyType          { Native, Sandboxed, Standalone, Embedded }
enum WebAssemblyAttackType    { CodeInjection, MemoryCorruption, SideChannel, DenialOfService }
enum WebAssemblyDefenseType   { Sandboxing, Validation, RateLimit, ContinuousMonitoring }

error WASM__NoModule();
error WASM__InvalidSignature();
error WASM__TooManyRequests();
error WASM__AnomalyDetected();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE EXECUTOR
//
//    • ❌ no checks: any bytecode may be loaded and executed → CodeInjection
////////////////////////////////////////////////////////////////////////////////
contract WASMVuln {
    mapping(bytes32 => bytes) public modules;

    event ModuleLoaded(
        address indexed who,
        bytes32            moduleId,
        WebAssemblyType    wtype,
        WebAssemblyAttackType attack
    );
    event ModuleExecuted(
        address indexed who,
        bytes32            moduleId,
        bytes              input,
        WebAssemblyType    wtype,
        WebAssemblyAttackType attack
    );

    function loadModule(bytes32 moduleId, bytes calldata wasm, WebAssemblyType wtype) external {
        modules[moduleId] = wasm;
        emit ModuleLoaded(msg.sender, moduleId, wtype, WebAssemblyAttackType.CodeInjection);
    }

    function executeModule(bytes32 moduleId, bytes calldata input, WebAssemblyType wtype) external {
        require(modules[moduleId].length != 0, "no module");
        // naive: pretend to call into a WASM VM
        emit ModuleExecuted(msg.sender, moduleId, input, wtype, WebAssemblyAttackType.MemoryCorruption);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates injection of malicious module & side‐channel probing
////////////////////////////////////////////////////////////////////////////////
contract Attack_WASM {
    WASMVuln public target;
    bytes32 public lastModule;
    bytes   public lastInput;

    constructor(WASMVuln _t) { target = _t; }

    function inject(bytes32 moduleId, bytes calldata wasm) external {
        // attacker loads malicious code
        target.loadModule(moduleId, wasm, WebAssemblyType.Native);
        lastModule = moduleId;
    }

    function sideChannel(bytes calldata inp) external {
        // attacker probes with crafted input
        target.executeModule(lastModule, inp, WebAssemblyType.Native);
        lastInput = inp;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH SANDBOXING
//
//    • ✅ Defense: Sandboxing – only approved modules may execute
////////////////////////////////////////////////////////////////////////////////
contract WASMSafeSandbox {
    mapping(bytes32 => bytes) public modules;
    mapping(bytes32 => bool)  public allowed;
    event ModuleLoaded(
        address indexed who,
        bytes32            moduleId,
        WebAssemblyType    wtype,
        WebAssemblyDefenseType defense
    );
    event ModuleExecuted(
        address indexed who,
        bytes32            moduleId,
        bytes              input,
        WebAssemblyType    wtype,
        WebAssemblyDefenseType defense
    );

    function allowModule(bytes32 moduleId, bool ok) external {
        // admin stub: msg.sender is admin
        allowed[moduleId] = ok;
    }

    function loadModule(bytes32 moduleId, bytes calldata wasm, WebAssemblyType wtype) external {
        modules[moduleId] = wasm;
        emit ModuleLoaded(msg.sender, moduleId, wtype, WebAssemblyDefenseType.Sandboxing);
    }

    function executeModule(bytes32 moduleId, bytes calldata input, WebAssemblyType wtype) external {
        require(allowed[moduleId], "sandbox: not allowed");
        emit ModuleExecuted(msg.sender, moduleId, input, wtype, WebAssemblyDefenseType.Sandboxing);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE‐LIMIT
//
//    • ✅ Defense: Validation – require signer’s approval  
//               RateLimit – cap executions per block
////////////////////////////////////////////////////////////////////////////////
contract WASMSafeValidateRate {
    address public signer;
    mapping(bytes32 => bytes) public modules;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event ModuleLoaded(
        address indexed who,
        bytes32            moduleId,
        WebAssemblyDefenseType defense
    );
    event ModuleExecuted(
        address indexed who,
        bytes32            moduleId,
        bytes              input,
        WebAssemblyDefenseType defense
    );

    error WASM__InvalidSignature();
    error WASM__TooManyRequests();

    constructor(address _signer) { signer = _signer; }

    function loadModule(
        bytes32 moduleId,
        bytes calldata wasm,
        bytes calldata sig
    ) external {
        // verify signature over moduleId||wasm
        bytes32 msgHash = keccak256(abi.encodePacked(moduleId, wasm));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert WASM__InvalidSignature();

        modules[moduleId] = wasm;
        emit ModuleLoaded(msg.sender, moduleId, WebAssemblyDefenseType.Validation);
    }

    function executeModule(bytes32 moduleId, bytes calldata input) external {
        require(modules[moduleId].length != 0, "no module");
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WASM__TooManyRequests();

        emit ModuleExecuted(msg.sender, moduleId, input, WebAssemblyDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH CONTINUOUS MONITORING
//
//    • ✅ Defense: ContinuousMonitoring – log anomalies and executions
////////////////////////////////////////////////////////////////////////////////
contract WASMSafeAdvanced {
    mapping(address => uint256) public execCount;
    mapping(address => uint256) public lastAnomaly;
    mapping(bytes32 => bytes) public modules;

    event ModuleLoaded(
        address indexed who,
        bytes32            moduleId,
        WebAssemblyDefenseType defense
    );
    event ModuleExecuted(
        address indexed who,
        bytes32            moduleId,
        bytes              input,
        WebAssemblyDefenseType defense
    );
    event Anomaly(
        address indexed who,
        string             reason,
        WebAssemblyDefenseType defense
    );

    error WASM__NoModule();

    function loadModule(bytes32 moduleId, bytes calldata wasm) external {
        modules[moduleId] = wasm;
        emit ModuleLoaded(msg.sender, moduleId, WebAssemblyDefenseType.ContinuousMonitoring);
    }

    function executeModule(bytes32 moduleId, bytes calldata input) external {
        if (modules[moduleId].length == 0) revert WASM__NoModule();
        // monitor for unusually high execution counts
        execCount[msg.sender]++;
        if (execCount[msg.sender] > 100) {
            lastAnomaly[msg.sender] = block.number;
            emit Anomaly(msg.sender, "excessive executions", WebAssemblyDefenseType.ContinuousMonitoring);
        }
        emit ModuleExecuted(msg.sender, moduleId, input, WebAssemblyDefenseType.ContinuousMonitoring);
    }
}
