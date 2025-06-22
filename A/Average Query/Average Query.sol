// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AverageQuerySuite.sol
/// @notice On-chain analogues of “Average Query” computation patterns:
///   Types: SingleField, MultiField, SlidingWindow  
///   AttackTypes: TimingAttack, Injection, Overflow  
///   DefenseTypes: InputValidation, RateLimit, SafeMath, QuerySanitization  

enum AverageQueryType          { SingleField, MultiField, SlidingWindow }
enum AverageQueryAttackType    { TimingAttack, Injection, Overflow }
enum AverageQueryDefenseType   { InputValidation, RateLimit, SafeMath, QuerySanitization }

error AQ__InvalidInput();
error AQ__TooManyRequests();
error AQ__OverflowDetected();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE AVERAGE CALCULATOR
//
//    • no input checks, simple division → Overflow
//    • Attack: Overflow
////////////////////////////////////////////////////////////////////////////////
contract AverageQueryVuln {
    event AverageComputed(
        address indexed who,
        AverageQueryType    qtype,
        uint256[]           data,
        uint256             avg,
        AverageQueryAttackType attack
    );

    function computeSingle(uint256[] calldata data) external {
        uint256 sum = 0;
        for (uint256 i = 0; i < data.length; i++) {
            sum += data[i];
        }
        uint256 avg = data.length > 0 ? sum / data.length : 0;
        emit AverageComputed(msg.sender, AverageQueryType.SingleField, data, avg, AverageQueryAttackType.Overflow);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates overflow by providing large values
////////////////////////////////////////////////////////////////////////////////
contract Attack_AverageQuery {
    AverageQueryVuln public target;
    constructor(AverageQueryVuln _t) { target = _t; }

    function overflowAttack(uint256[] calldata data) external {
        // craft data such that sum overflows
        target.computeSingle(data);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH INPUT VALIDATION
//
//    • Defense: InputValidation – limit data size and value range
////////////////////////////////////////////////////////////////////////////////
contract AverageQuerySafeValidation {
    uint256 public constant MAX_LEN = 100;
    uint256 public constant MAX_VAL = 1e18;
    event AverageComputed(
        address indexed who,
        AverageQueryType    qtype,
        uint256[]           data,
        uint256             avg,
        AverageQueryDefenseType defense
    );

    error AQ__InvalidInput();

    function computeSingle(uint256[] calldata data) external {
        if (data.length == 0 || data.length > MAX_LEN) revert AQ__InvalidInput();
        uint256 sum = 0;
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] > MAX_VAL) revert AQ__InvalidInput();
            sum += data[i];
        }
        uint256 avg = sum / data.length;
        emit AverageComputed(msg.sender, AverageQueryType.SingleField, data, avg, AverageQueryDefenseType.InputValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RATE-LIMITING
//
//    • Defense: RateLimit – cap calls per block per user
////////////////////////////////////////////////////////////////////////////////
contract AverageQuerySafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event AverageComputed(
        address indexed who,
        AverageQueryType    qtype,
        uint256[]           data,
        uint256             avg,
        AverageQueryDefenseType defense
    );

    error AQ__TooManyRequests();

    function computeSingle(uint256[] calldata data) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert AQ__TooManyRequests();

        uint256 sum = 0;
        for (uint256 i = 0; i < data.length; i++) {
            sum += data[i];
        }
        uint256 avg = data.length > 0 ? sum / data.length : 0;
        emit AverageComputed(msg.sender, AverageQueryType.SingleField, data, avg, AverageQueryDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE WITH SAFEMATH & SLIDING WINDOW
//
//    • Defense: SafeMath – use overflow-checked operations  
//               SlidingWindow – compute average over last N entries
////////////////////////////////////////////////////////////////////////////////
import "@openzeppelin/contracts/utils/math/SafeMath.sol";

contract AverageQuerySafeAdvanced {
    using SafeMath for uint256;

    uint256 public windowSize = 10;
    mapping(address => uint256[]) private history;

    event AverageComputed(
        address indexed who,
        AverageQueryType    qtype,
        uint256             avg,
        AverageQueryDefenseType defense
    );

    error AQ__OverflowDetected();

    function recordAndCompute(uint256 value) external {
        // record in sliding window
        uint256[] storage hist = history[msg.sender];
        if (hist.length == windowSize) {
            // drop oldest
            for (uint256 i = 1; i < hist.length; i++) {
                hist[i - 1] = hist[i];
            }
            hist[windowSize - 1] = value;
        } else {
            hist.push(value);
        }

        // compute average with SafeMath
        uint256 sum = 0;
        for (uint256 i = 0; i < hist.length; i++) {
            sum = sum.add(hist[i]);
        }
        uint256 avg = sum.div(hist.length);
        emit AverageComputed(msg.sender, AverageQueryType.SlidingWindow, avg, AverageQueryDefenseType.SafeMath);
    }
}
