// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AdvancedThreatSimulationSuite.sol
/// @notice On‐chain analogues of “Advanced Threat Simulation” patterns:
///   Types: Network, Host, Application, Cloud  
///   AttackTypes: Misconfiguration, SocialEngineering, MalwareInjection, Evasion  
///   DefenseTypes: AccessControl, Logging, Sandbox, RateLimit, SignatureValidation

enum ATSimType            { Network, Host, Application, Cloud }
enum ATSimAttackType      { Misconfiguration, SocialEngineering, MalwareInjection, Evasion }
enum ATSimDefenseType     { AccessControl, Logging, Sandbox, RateLimit, SignatureValidation }

error ATS__NotOwner();
error ATS__InvalidScenario();
error ATS__TooManyRequests();
error ATS__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SIMULATION MANAGER
//    • ❌ no checks: anyone may create/run scenarios → Misconfiguration
////////////////////////////////////////////////////////////////////////////////
contract ATSimVuln {
    struct Scenario { uint256 id; ATSimType simType; string details; }
    mapping(uint256 => Scenario) public scenarios;

    event ScenarioCreated(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimAttackType   attack
    );
    event ScenarioRun(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimAttackType   attack
    );

    function createScenario(uint256 scenarioId, ATSimType simType, string calldata details) external {
        scenarios[scenarioId] = Scenario(scenarioId, simType, details);
        emit ScenarioCreated(msg.sender, scenarioId, simType, ATSimAttackType.Misconfiguration);
    }

    function runScenario(uint256 scenarioId) external {
        Scenario storage s = scenarios[scenarioId];
        emit ScenarioRun(msg.sender, s.id, s.simType, ATSimAttackType.MalwareInjection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates misconfig, social engineering, malware injection, evasion
////////////////////////////////////////////////////////////////////////////////
contract Attack_ATSim {
    ATSimVuln public target;
    uint256 public lastId;

    constructor(ATSimVuln _t) { target = _t; }

    function spoofCreate(uint256 id) external {
        target.createScenario(id, ATSimType.Network, "fake config");
        lastId = id;
    }

    function socialEngineer(uint256 id) external {
        target.runScenario(id);
    }

    function injectMalware(uint256 id) external {
        target.runScenario(id);
    }

    function evade(uint256 id) external {
        target.runScenario(id);
    }

    function replay() external {
        target.runScenario(lastId);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may create/run
////////////////////////////////////////////////////////////////////////////////
contract ATSimSafeAccess {
    struct Scenario { uint256 id; ATSimType simType; string details; }
    mapping(uint256 => Scenario) public scenarios;
    address public owner;

    event ScenarioCreated(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimDefenseType  defense
    );
    event ScenarioRun(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimDefenseType  defense
    );

    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        if (msg.sender != owner) revert ATS__NotOwner();
        _;
    }

    function createScenario(uint256 scenarioId, ATSimType simType, string calldata details)
        external onlyOwner
    {
        scenarios[scenarioId] = Scenario(scenarioId, simType, details);
        emit ScenarioCreated(msg.sender, scenarioId, simType, ATSimDefenseType.AccessControl);
    }

    function runScenario(uint256 scenarioId) external onlyOwner {
        Scenario storage s = scenarios[scenarioId];
        emit ScenarioRun(msg.sender, s.id, s.simType, ATSimDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH SANDBOX & RATE LIMIT
//    • ✅ Defense: Sandbox – isolate scenario runs  
//               RateLimit – cap runs per block
////////////////////////////////////////////////////////////////////////////////
contract ATSimSafeValidate {
    struct Scenario { uint256 id; ATSimType simType; string details; }
    mapping(uint256 => Scenario) public scenarios;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public runsInBlock;
    uint256 public constant MAX_RUNS = 3;

    event ScenarioCreated(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimDefenseType  defense
    );
    event ScenarioRun(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimDefenseType  defense
    );

    error ATS__InvalidScenario();
    error ATS__TooManyRequests();

    function createScenario(uint256 scenarioId, ATSimType simType, string calldata details) external {
        scenarios[scenarioId] = Scenario(scenarioId, simType, details);
        emit ScenarioCreated(msg.sender, scenarioId, simType, ATSimDefenseType.Logging);
    }

    function runScenario(uint256 scenarioId) external {
        if (bytes(scenarios[scenarioId].details).length == 0) revert ATS__InvalidScenario();

        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            runsInBlock[msg.sender] = 0;
        }
        runsInBlock[msg.sender]++;
        if (runsInBlock[msg.sender] > MAX_RUNS) revert ATS__TooManyRequests();

        // sandbox stub: no state changes outside this context
        emit ScenarioRun(msg.sender, scenarioId, scenarios[scenarioId].simType, ATSimDefenseType.Sandbox);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed scenarios  
//               AuditLogging      – log every creation/run
////////////////////////////////////////////////////////////////////////////////
contract ATSimSafeAdvanced {
    struct Scenario { uint256 id; ATSimType simType; string details; }
    mapping(uint256 => Scenario) public scenarios;
    address public signer;

    event ScenarioCreated(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimDefenseType  defense
    );
    event ScenarioRun(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimDefenseType  defense
    );
    event AuditLog(
        address indexed who,
        uint256           scenarioId,
        ATSimType         simType,
        ATSimDefenseType  defense
    );

    error ATS__InvalidSignature();

    constructor(address _signer) { signer = _signer; }

    function createScenario(
        uint256 scenarioId,
        ATSimType simType,
        string calldata details,
        bytes calldata sig
    ) external {
        // verify signature over (scenarioId||simType||details)
        bytes32 h = keccak256(abi.encodePacked(scenarioId, simType, details));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert ATS__InvalidSignature();

        scenarios[scenarioId] = Scenario(scenarioId, simType, details);
        emit ScenarioCreated(msg.sender, scenarioId, simType, ATSimDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, scenarioId, simType, ATSimDefenseType.AuditLogging);
    }

    function runScenario(uint256 scenarioId, bytes calldata sig) external {
        Scenario storage s = scenarios[scenarioId];
        // verify signature over run intent
        bytes32 h = keccak256(abi.encodePacked("RUN", scenarioId));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 sgn) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, sgn) != signer) revert ATS__InvalidSignature();

        emit ScenarioRun(msg.sender, s.id, s.simType, ATSimDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, s.id, s.simType, ATSimDefenseType.AuditLogging);
    }
}
