// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AutomaticDataProcessingSuite.sol
/// @notice On-chain analogues of “Automatic Data Processing” patterns:
///   Types: Batch, RealTime, Stream  
///   AttackTypes: DataTampering, ReplayAttack, UnauthorizedAccess  
///   DefenseTypes: InputValidation, AccessControl, IntegrityCheck, RateLimit  

enum AutomaticDataProcessingType   { Batch, RealTime, Stream }
enum ADPAttackType                 { DataTampering, ReplayAttack, UnauthorizedAccess }
enum ADPDefenseType                { InputValidation, AccessControl, IntegrityCheck, RateLimit }

error ADP__InvalidInput();
error ADP__Unauthorized();
error ADP__Tampered();
error ADP__TooManyRequests();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE PROCESSOR
///
///    • ❌ no checks: any data accepted and processed → DataTampering
///─────────────────────────────────────────────────────────────────────────────
contract ADPVuln {
    event Processed(
        address indexed who,
        AutomaticDataProcessingType dtype,
        bytes data,
        ADPAttackType attack
    );

    function processData(AutomaticDataProcessingType dtype, bytes calldata data) external {
        // no validation
        emit Processed(msg.sender, dtype, data, ADPAttackType.DataTampering);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • simulates tampering and replay
///─────────────────────────────────────────────────────────────────────────────
contract Attack_ADP {
    ADPVuln public target;
    bytes public lastData;

    constructor(ADPVuln _t) { target = _t; }

    function tamper(AutomaticDataProcessingType dtype, bytes calldata fakeData) external {
        target.processData(dtype, fakeData);
    }

    function replay(AutomaticDataProcessingType dtype) external {
        target.processData(dtype, lastData);
    }

    function capture(bytes calldata data) external {
        lastData = data;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE WITH INPUT VALIDATION
///
///    • ✅ Defense: InputValidation – enforce size and content limits
///─────────────────────────────────────────────────────────────────────────────
contract ADPSafeValidation {
    uint256 public constant MAX_SIZE = 1024;
    event Processed(
        address indexed who,
        AutomaticDataProcessingType dtype,
        bytes data,
        ADPDefenseType defense
    );

    function processData(AutomaticDataProcessingType dtype, bytes calldata data) external {
        // validate size
        if (data.length == 0 || data.length > MAX_SIZE) revert ADP__InvalidInput();
        // simple content check: no zero-byte
        for (uint i = 0; i < data.length; i++) {
            if (data[i] == 0x00) revert ADP__InvalidInput();
        }
        emit Processed(msg.sender, dtype, data, ADPDefenseType.InputValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE WITH ACCESS CONTROL
///
///    • ✅ Defense: AccessControl – only whitelisted callers
///─────────────────────────────────────────────────────────────────────────────
contract ADPSafeAccess {
    mapping(address => bool) public allowed;
    event Processed(
        address indexed who,
        AutomaticDataProcessingType dtype,
        bytes data,
        ADPDefenseType defense
    );

    error ADP__Unauthorized();

    constructor() {
        allowed[msg.sender] = true;
    }

    function setAllowed(address who, bool ok) external {
        require(allowed[msg.sender], "only admin");
        allowed[who] = ok;
    }

    function processData(AutomaticDataProcessingType dtype, bytes calldata data) external {
        if (!allowed[msg.sender]) revert ADP__Unauthorized();
        emit Processed(msg.sender, dtype, data, ADPDefenseType.AccessControl);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED WITH INTEGRITY CHECK & RATE LIMIT
///
///    • ✅ Defense: IntegrityCheck – require signature over data  
///               RateLimit – cap calls per block
///─────────────────────────────────────────────────────────────────────────────
contract ADPSafeAdvanced {
    address public signer;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    event Processed(
        address indexed who,
        AutomaticDataProcessingType dtype,
        bytes data,
        ADPDefenseType defense
    );

    error ADP__TooManyRequests();
    error ADP__Tampered();

    constructor(address _signer) {
        signer = _signer;
    }

    function processData(
        AutomaticDataProcessingType dtype,
        bytes calldata data,
        bytes calldata sig
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_PER_BLOCK) revert ADP__TooManyRequests();

        // integrity check: verify signature over data
        bytes32 msgHash = keccak256(abi.encodePacked(data));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) revert ADP__Tampered();

        emit Processed(msg.sender, dtype, data, ADPDefenseType.IntegrityCheck);
    }
}
