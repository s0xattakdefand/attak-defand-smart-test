// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataAggregationSuite.sol
/// @notice On‑chain analogues of “Data Aggregation” patterns:
///   Types: Sum, Average, Max, Min  
///   AttackTypes: Poisoning, Flood, Replay, BiasInjection  
///   DefenseTypes: AccessControl, RateLimit, IntegrityCheck, OutlierFilter  

enum DataAggregationType        { Sum, Average, Max, Min }
enum DataAggregationAttackType  { Poisoning, Flood, Replay, BiasInjection }
enum DataAggregationDefenseType { AccessControl, RateLimit, IntegrityCheck, OutlierFilter }

error AGG__NotAuthorized();
error AGG__TooMany();
error AGG__InvalidData();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE AGGREGATOR
///
///    • no controls: any caller may submit any value, unlimited times  
///    • Attack: Poisoning, Flood  
///─────────────────────────────────────────────────────────────────────────────
contract DataAggregationVuln {
    mapping(uint256 => uint256[]) public dataPoints;
    event DataAdded(
        uint256 indexed id,
        uint256         value,
        DataAggregationAttackType attack
    );

    /// ❌ freely accept any value
    function addData(uint256 id, uint256 value) external {
        dataPoints[id].push(value);
        emit DataAdded(id, value, DataAggregationAttackType.Poisoning);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • demonstrates flooding and replay of old values  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DataAggregation {
    DataAggregationVuln public target;
    constructor(DataAggregationVuln _t) { target = _t; }

    /// flood with many values
    function flood(uint256 id, uint256[] calldata values) external {
        for (uint256 i = 0; i < values.length; i++) {
            target.addData(id, values[i]);
        }
    }

    /// replay a previously seen value
    function replay(uint256 id, uint256 value) external {
        target.addData(id, value);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE AGGREGATOR WITH ACCESS CONTROL & RATE‑LIMIT
///
///    • Defense: AccessControl – only authorized sensors may submit  
///               RateLimit – cap submissions per block per sensor  
///─────────────────────────────────────────────────────────────────────────────
contract DataAggregationSafe {
    mapping(address => bool)    public authorized;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 10;
    mapping(uint256 => uint256[]) public dataPoints;

    event DataAdded(
        uint256 indexed id,
        uint256         value,
        DataAggregationDefenseType defense
    );

    error AGG__TooMany();
    error AGG__NotAuthorized();

    /// owner manages authorized sensors
    address public owner;
    constructor() { owner = msg.sender; }

    function setAuthorized(address sensor, bool ok) external {
        require(msg.sender == owner, "only owner");
        authorized[sensor] = ok;
    }

    /// ✅ only authorized, rate‑limited submissions
    function addData(uint256 id, uint256 value) external {
        if (!authorized[msg.sender]) revert AGG__NotAuthorized();

        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert AGG__TooMany();

        dataPoints[id].push(value);
        emit DataAdded(id, value, DataAggregationDefenseType.RateLimit);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE AGGREGATOR WITH INTEGRITY CHECK & OUTLIER FILTER
///
///    • Defense: IntegrityCheck – accept only values within configured range  
///               OutlierFilter – reject extreme outliers  
///─────────────────────────────────────────────────────────────────────────────
contract DataAggregationSafeIntegrity {
    mapping(uint256 => uint256[]) public dataPoints;
    uint256 public minValue;
    uint256 public maxValue;
    uint256 public constant MAX_DEVIATION = 100; // example tolerance

    event DataAdded(
        uint256 indexed id,
        uint256         value,
        DataAggregationDefenseType defense
    );
    error AGG__InvalidData();

    constructor(uint256 _minValue, uint256 _maxValue) {
        minValue = _minValue;
        maxValue = _maxValue;
    }

    /// ✅ enforce value ∈ [minValue, maxValue] and within MAX_DEVIATION of previous
    function addData(uint256 id, uint256 value) external {
        if (value < minValue || value > maxValue) revert AGG__InvalidData();
        uint256[] storage arr = dataPoints[id];
        if (arr.length > 0) {
            uint256 last = arr[arr.length - 1];
            uint256 diff = value > last ? value - last : last - value;
            if (diff > MAX_DEVIATION) revert AGG__InvalidData();
        }
        arr.push(value);
        emit DataAdded(id, value, DataAggregationDefenseType.IntegrityCheck);
    }
}
