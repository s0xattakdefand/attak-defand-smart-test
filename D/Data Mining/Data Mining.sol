// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataMiningSuite.sol
/// @notice On‑chain analogues of “Data Mining” patterns:
///   Types: Classification, Clustering, Association, Regression  
///   AttackTypes: Poisoning, Evasion, Extraction, Inference  
///   DefenseTypes: Sanitization, DifferentialPrivacy, AccessControl, RateLimit  

enum DataMiningType         { Classification, Clustering, Association, Regression }
enum DataMiningAttackType   { Poisoning, Evasion, Extraction, Inference }
enum DataMiningDefenseType  { Sanitization, DifferentialPrivacy, AccessControl, RateLimit }

error DMN__NotAuthorized();
error DMN__TooManySubmissions();
error DMN__InvalidInput();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DATA MINER
///
///    • accepts arbitrary data submissions, no checks → Poisoning
///─────────────────────────────────────────────────────────────────────────────
contract DataMiningVuln {
    // modelId → raw data blobs
    mapping(uint256 => bytes[]) public dataset;
    event DataSubmitted(
        address indexed who,
        uint256 indexed modelId,
        bytes          data,
        DataMiningAttackType attack
    );

    /// ❌ no validation: attacker can poison the dataset
    function submitData(uint256 modelId, bytes calldata data) external {
        dataset[modelId].push(data);
        emit DataSubmitted(msg.sender, modelId, data, DataMiningAttackType.Poisoning);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • demonstrates data poisoning and model extraction
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DataMining {
    DataMiningVuln public target;
    constructor(DataMiningVuln _t) { target = _t; }

    /// flood model with malicious data
    function poison(uint256 modelId, bytes[] calldata malData) external {
        for (uint i = 0; i < malData.length; i++) {
            target.submitData(modelId, malData[i]);
        }
    }

    /// attempt to extract model by repeatedly querying (stub)
    function extract(uint256 modelId) external view returns (bytes[] memory) {
        // in a real attack, would infer model parameters
        return target.dataset(modelId);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DATA MINER (ACCESS CONTROL)
///
///    • only authorized sensors may submit → AccessControl
///─────────────────────────────────────────────────────────────────────────────
contract DataMiningSafe {
    mapping(address => bool)    public authorized;
    uint256[] public models;
    event DataSubmitted(
        address indexed who,
        uint256 indexed modelId,
        bytes          data,
        DataMiningDefenseType defense
    );

    error DMN__NotAuthorized();

    /// owner manages sensors
    address public owner;
    constructor() { owner = msg.sender; }

    function setAuthorized(address sensor, bool ok) external {
        require(msg.sender == owner, "only owner");
        authorized[sensor] = ok;
    }

    /// ✅ only authorized callers may submit
    function submitData(uint256 modelId, bytes calldata data) external {
        if (!authorized[msg.sender]) revert DMN__NotAuthorized();
        emit DataSubmitted(msg.sender, modelId, data, DataMiningDefenseType.AccessControl);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE DATA MINER WITH SANITIZATION & DIFFERENTIAL PRIVACY + RATE‑LIMIT
///
///    • Defense: Sanitization (size limit)  
///               DifferentialPrivacy (add noise stub)  
///               RateLimit (cap submissions per block)
///─────────────────────────────────────────────────────────────────────────────
contract DataMiningSafeAdvanced {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;

    uint256 public constant MAX_PER_BLOCK = 10;
    uint256 public constant MAX_DATA_SIZE = 2048;

    event DataSubmitted(
        address indexed who,
        uint256 indexed modelId,
        bytes          sanitized,
        bytes32        noiseStamp,
        DataMiningDefenseType defense
    );

    error DMN__TooManySubmissions();
    error DMN__InvalidInput();

    /// ✅ enforce size limit, rate‑limit per block, and emit DP noise stamp
    function submitData(uint256 modelId, bytes calldata data) external {
        // sanitization
        if (data.length == 0 || data.length > MAX_DATA_SIZE) revert DMN__InvalidInput();

        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DMN__TooManySubmissions();

        // stub differential privacy: noiseStamp = keccak(data||block)
        bytes32 noiseStamp = keccak256(abi.encodePacked(data, blockhash(block.number - 1)));

        emit DataSubmitted(msg.sender, modelId, data, noiseStamp, DataMiningDefenseType.DifferentialPrivacy);
    }
}
