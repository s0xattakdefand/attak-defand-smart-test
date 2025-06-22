// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WeakestJudgmentAlgorithmSuite.sol
/// @notice On‐chain analogues of “Weakest Judgment Algorithm” fusion patterns:
///   Types: Binary, MultiClass, Weighted, Probabilistic  
///   AttackTypes: DataPoisoning, LabelFlip, AdversarialEvasion, NoiseInjection  
///   DefenseTypes: AnomalyDetection, RobustAggregation, ThresholdValidation, RateLimit

enum WeakestJudgmentType        { Binary, MultiClass, Weighted, Probabilistic }
enum WeakestJudgmentAttackType  { DataPoisoning, LabelFlip, AdversarialEvasion, NoiseInjection }
enum WeakestJudgmentDefenseType { AnomalyDetection, RobustAggregation, ThresholdValidation, RateLimit }

error WJA__NoInputs();
error WJA__AnomalyDetected();
error WJA__ThresholdFailed();
error WJA__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE FUSION
//    • ❌ no checks: picks minimal support blindly → DataPoisoning
////////////////////////////////////////////////////////////////////////////////
contract WJAVuln {
    event Judgment(
        address indexed who,
        WeakestJudgmentType    jtype,
        uint256[]              inputs,
        uint256                result,
        WeakestJudgmentAttackType attack
    );

    function fuse(WeakestJudgmentType jtype, uint256[] calldata inputs) external {
        require(inputs.length > 0, "no inputs");
        // pick minimal value as weakest judgment
        uint256 min = inputs[0];
        for (uint i = 1; i < inputs.length; i++) {
            if (inputs[i] < min) min = inputs[i];
        }
        emit Judgment(msg.sender, jtype, inputs, min, WeakestJudgmentAttackType.DataPoisoning);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates label flipping & noise injection
////////////////////////////////////////////////////////////////////////////////
contract Attack_WJA {
    WJAVuln public target;

    constructor(WJAVuln _t) { target = _t; }

    function poison(uint256[] calldata inputs) external {
        // flip extreme labels to low values
        uint[] memory flipped = inputs;
        for (uint i = 0; i < flipped.length; i++) {
            if (flipped[i] > 0) flipped[i] = 0;
        }
        target.fuse(WeakestJudgmentType.MultiClass, flipped);
    }

    function injectNoise(uint256[] calldata inputs) external {
        // inject zeros
        uint256[] memory noisy = new uint256[](inputs.length + 1);
        for (uint i = 0; i < inputs.length; i++) noisy[i] = inputs[i];
        noisy[inputs.length] = 0;
        target.fuse(WeakestJudgmentType.Weighted, noisy);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ANOMALY DETECTION
//    • ✅ Defense: AnomalyDetection – reject outlier inputs
////////////////////////////////////////////////////////////////////////////////
contract WJASafeAnomaly {
    event Judgment(
        address indexed who,
        WeakestJudgmentType    jtype,
        uint256[]              filtered,
        uint256                result,
        WeakestJudgmentDefenseType defense
    );

    error WJA__AnomalyDetected();

    function fuse(WeakestJudgmentType jtype, uint256[] calldata inputs) external {
        require(inputs.length > 0, "no inputs");
        // filter out values that deviate beyond ±50% of median
        uint256[] memory copy = inputs;
        // compute median (naïve sort stub)
        for (uint i = 0; i < copy.length; i++) {
            for (uint j = i + 1; j < copy.length; j++) {
                if (copy[j] < copy[i]) {
                    (copy[i], copy[j]) = (copy[j], copy[i]);
                }
            }
        }
        uint256 med = copy[copy.length/2];
        uint256 count;
        for (uint i = 0; i < inputs.length; i++) {
            if (inputs[i] >= med/2 && inputs[i] <= med + med/2) {
                count++;
            }
        }
        require(count > 0, "all anomalous");
        uint256[] memory filtered = new uint256[](count);
        uint idx = 0;
        for (uint i = 0; i < inputs.length; i++) {
            if (inputs[i] >= med/2 && inputs[i] <= med + med/2) {
                filtered[idx++] = inputs[i];
            }
        }
        // pick minimal of filtered
        uint256 min = filtered[0];
        for (uint i = 1; i < filtered.length; i++) {
            if (filtered[i] < min) min = filtered[i];
        }
        emit Judgment(msg.sender, jtype, filtered, min, WeakestJudgmentDefenseType.AnomalyDetection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ROBUST AGGREGATION
//    • ✅ Defense: RobustAggregation – use second‐smallest value
////////////////////////////////////////////////////////////////////////////////
contract WJASafeRobust {
    event Judgment(
        address indexed who,
        WeakestJudgmentType    jtype,
        uint256[]              inputs,
        uint256                result,
        WeakestJudgmentDefenseType defense
    );

    function fuse(WeakestJudgmentType jtype, uint256[] calldata inputs) external {
        require(inputs.length > 1, "need >1 inputs");
        // find first and second minima
        uint256 min1 = type(uint256).max;
        uint256 min2 = type(uint256).max;
        for (uint i = 0; i < inputs.length; i++) {
            uint256 v = inputs[i];
            if (v < min1) {
                min2 = min1;
                min1 = v;
            } else if (v < min2) {
                min2 = v;
            }
        }
        emit Judgment(msg.sender, jtype, inputs, min2, WeakestJudgmentDefenseType.RobustAggregation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH THRESHOLD VALIDATION & RATE‐LIMIT
//    • ✅ Defense: ThresholdValidation – require min support ≥ threshold  
//               RateLimit – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract WJASafeAdvanced {
    uint256 public threshold;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event Judgment(
        address indexed who,
        WeakestJudgmentType    jtype,
        uint256[]              inputs,
        uint256                result,
        WeakestJudgmentDefenseType defense
    );

    error WJA__ThresholdFailed();
    error WJA__TooManyRequests();

    constructor(uint256 _threshold) {
        threshold = _threshold;
    }

    function fuse(WeakestJudgmentType jtype, uint256[] calldata inputs) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WJA__TooManyRequests();

        require(inputs.length >= threshold, "not enough support");
        // pick minimal
        uint256 min = inputs[0];
        for (uint i = 1; i < inputs.length; i++) {
            if (inputs[i] < min) min = inputs[i];
        }
        // ensure result ≥ threshold value
        if (min < threshold) revert WJA__ThresholdFailed();
        emit Judgment(msg.sender, jtype, inputs, min, WeakestJudgmentDefenseType.ThresholdValidation);
    }
}
