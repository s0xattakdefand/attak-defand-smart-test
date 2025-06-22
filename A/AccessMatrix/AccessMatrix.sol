// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ActiveMatrixSuite.sol
/// @notice On-chain analogues of “Active Matrix” display patterns:
///   Types: TFT, OLED, MicroLED, LTPS  
///   AttackTypes: PixelStuck, BurnIn, EMIInterference, FaultInjection  
///   DefenseTypes: RefreshRate, ErrorCorrection, Shielding, Redundancy  

enum ActiveMatrixType          { TFT, OLED, MicroLED, LTPS }
enum ActiveMatrixAttackType    { PixelStuck, BurnIn, EMIInterference, FaultInjection }
enum ActiveMatrixDefenseType   { RefreshRate, ErrorCorrection, Shielding, Redundancy }

error AM__TooHeavyFrame();
error AM__BadECC();
error AM__NotAllowed();
error AM__AlreadyRefreshed();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE RENDERER
///
///    • no refresh or correction → pixels burn in or stuck  
///    • Attack: BurnIn, PixelStuck
///─────────────────────────────────────────────────────────────────────────────
contract ActiveMatrixVuln {
    event FrameRendered(
        address indexed who,
        ActiveMatrixType    mtype,
        uint256             frameSize,
        ActiveMatrixAttackType attack
    );

    function renderFrame(ActiveMatrixType mtype, uint256 frameSize) external {
        // ❌ no rate-limit: heavy frames cause burn-in
        emit FrameRendered(msg.sender, mtype, frameSize, ActiveMatrixAttackType.BurnIn);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • Attack: send heavy frames & inject faults  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_ActiveMatrix {
    ActiveMatrixVuln public target;
    constructor(ActiveMatrixVuln _t) { target = _t; }

    function floodFrames(ActiveMatrixType mtype, uint256 frameSize, uint256 times) external {
        for (uint256 i = 0; i < times; i++) {
            target.renderFrame(mtype, frameSize);
        }
    }

    function injectFault(ActiveMatrixType mtype) external {
        // simulate fault injection by sending malformed frameSize
        target.renderFrame(mtype, type(uint256).max);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE REFRESH CONTROL
///
///    • Defense: RefreshRate – cap frames per block per caller  
///─────────────────────────────────────────────────────────────────────────────
contract ActiveMatrixSafeRefresh {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public framesInBlock;
    uint256 public constant MAX_FRAMES = 5;

    event FrameRendered(
        address indexed who,
        ActiveMatrixType    mtype,
        uint256             frameSize,
        ActiveMatrixDefenseType defense
    );
    error AM__TooManyFrames();

    function renderFrame(ActiveMatrixType mtype, uint256 frameSize) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            framesInBlock[msg.sender] = 0;
        }
        framesInBlock[msg.sender]++;
        if (framesInBlock[msg.sender] > MAX_FRAMES) revert AM__TooManyFrames();

        emit FrameRendered(msg.sender, mtype, frameSize, ActiveMatrixDefenseType.RefreshRate);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE ERROR CORRECTION
///
///    • Defense: ErrorCorrection – verify ECC code before display  
///─────────────────────────────────────────────────────────────────────────────
contract ActiveMatrixSafeECC {
    mapping(uint256 => bytes32) public eccCodes;
    event FrameRendered(
        address indexed who,
        ActiveMatrixType    mtype,
        uint256             frameSize,
        ActiveMatrixDefenseType defense
    );
    error AM__BadECC();

    /// owner registers ECC for a given frameSize
    function setECC(uint256 frameSize, bytes32 code) external {
        eccCodes[frameSize] = code;
    }

    function renderFrame(
        ActiveMatrixType mtype,
        uint256 frameSize,
        bytes32 providedECC
    ) external {
        bytes32 expected = eccCodes[frameSize];
        if (expected == bytes32(0) || expected != providedECC) revert AM__BadECC();
        emit FrameRendered(msg.sender, mtype, frameSize, ActiveMatrixDefenseType.ErrorCorrection);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 5) SAFE ADVANCED SHIELD + REDUNDANCY
///
///    • Defense: Shielding – only allowed callers  
///               Redundancy – duplicate frames for error recovery  
///─────────────────────────────────────────────────────────────────────────────
contract ActiveMatrixSafeAdvanced {
    mapping(address => bool)    public allowed;
    mapping(address => uint256) public redundantCount;
    address public owner;
    event FrameRendered(
        address indexed who,
        ActiveMatrixType    mtype,
        uint256             frameSize,
        ActiveMatrixDefenseType defense
    );
    error AM__NotAllowed();

    constructor() {
        owner = msg.sender;
        allowed[msg.sender] = true;
    }

    function setAllowed(address who, bool ok) external {
        if (msg.sender != owner) revert AM__NotAllowed();
        allowed[who] = ok;
    }

    function renderFrame(ActiveMatrixType mtype, uint256 frameSize, uint256 redundancy) external {
        if (!allowed[msg.sender]) revert AM__NotAllowed();
        // apply redundancy: emit multiple events
        for (uint i = 0; i < redundancy; i++) {
            emit FrameRendered(msg.sender, mtype, frameSize, ActiveMatrixDefenseType.Redundancy);
        }
    }
}
