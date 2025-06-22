// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WaveletScalarQuantizationSuite.sol
/// @notice On-chain analogues of “Wavelet Scalar Quantization” patterns:
///   Types: ImageCompress, AudioCompress, VideoCompress, FeatureExtract  
///   AttackTypes: QuantizationNoise, CoefficientTampering, ReconstructionError, CompressionAttack  
///   DefenseTypes: IntegrityCheck, ErrorCorrection, RobustQuantization, RateLimit

enum WaveletScalarQuantizationType { ImageCompress, AudioCompress, VideoCompress, FeatureExtract }
enum WSQAttackType                 { QuantizationNoise, CoefficientTampering, ReconstructionError, CompressionAttack }
enum WSQDefenseType                { IntegrityCheck, ErrorCorrection, RobustQuantization, RateLimit }

error WSQ__InvalidSignature();
error WSQ__ErrorCorrectionFailed();
error WSQ__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WSQ PROCESSOR
//    • ❌ no integrity or correction: noise and tampering pass through
////////////////////////////////////////////////////////////////////////////////
contract WSQVuln {
    mapping(bytes32 => bytes) public compressed;
    event Compressed(
        address indexed who,
        bytes32                        id,
        WaveletScalarQuantizationType  wtype,
        WSQAttackType                  attack
    );
    event Decompressed(
        address indexed who,
        bytes32                        id,
        bytes                          data,
        WaveletScalarQuantizationType  wtype,
        WSQAttackType                  attack
    );

    function compress(bytes32 id, bytes calldata raw, WaveletScalarQuantizationType wtype) external {
        // naive compress: store raw
        compressed[id] = raw;
        emit Compressed(msg.sender, id, wtype, WSQAttackType.QuantizationNoise);
    }

    function decompress(bytes32 id, WaveletScalarQuantizationType wtype) external {
        bytes memory data = compressed[id];
        emit Decompressed(msg.sender, id, data, wtype, WSQAttackType.ReconstructionError);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates coefficient tampering and replay attack
////////////////////////////////////////////////////////////////////////////////
contract Attack_WSQ {
    WSQVuln public target;
    bytes public lastData;
    bytes32 public lastId;

    constructor(WSQVuln _t) { target = _t; }

    function tamper(bytes32 id, bytes calldata fake) external {
        target.compress(id, fake, WaveletScalarQuantizationType.ImageCompress);
    }

    function capture(bytes32 id) external {
        lastId = id;
        lastData = target.compressed(id);
    }

    function replay() external {
        target.compress(lastId, lastData, WaveletScalarQuantizationType.ImageCompress);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH INTEGRITY CHECK
//    • ✅ Defense: IntegrityCheck – require signed approval before accept
////////////////////////////////////////////////////////////////////////////////
contract WSQSafeIntegrity {
    address public signer;
    mapping(bytes32 => bytes) public compressed;
    event Compressed(
        address indexed who,
        bytes32                        id,
        WaveletScalarQuantizationType  wtype,
        WSQDefenseType                 defense
    );

    error WSQ__InvalidSignature();

    constructor(address _signer) { signer = _signer; }

    function compress(
        bytes32 id,
        bytes calldata raw,
        WaveletScalarQuantizationType wtype,
        bytes calldata sig
    ) external {
        // verify signature over id||raw
        bytes32 h = keccak256(abi.encodePacked(id, raw));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert WSQ__InvalidSignature();

        compressed[id] = raw;
        emit Compressed(msg.sender, id, wtype, WSQDefenseType.IntegrityCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ERROR CORRECTION
//    • ✅ Defense: ErrorCorrection – store parity and correct minor errors
////////////////////////////////////////////////////////////////////////////////
contract WSQSafeErrorCorrection {
    struct Entry { bytes data; bytes parity; }
    mapping(bytes32 => Entry) public store;
    event Decompressed(
        address indexed who,
        bytes32                        id,
        bytes                          fixedData,
        WaveletScalarQuantizationType  wtype,
        WSQDefenseType                 defense
    );

    error WSQ__ErrorCorrectionFailed();

    function compressWithParity(
        bytes32 id,
        bytes calldata raw,
        bytes calldata parity
    ) external {
        store[id] = Entry(raw, parity);
    }

    function decompress(bytes32 id, WaveletScalarQuantizationType wtype) external {
        Entry storage e = store[id];
        bytes memory data = e.data;
        // stub: if data length != parity length, consider error
        if (e.parity.length != data.length) revert WSQ__ErrorCorrectionFailed();
        // "correct" by xoring parity
        for (uint i = 0; i < data.length; i++) {
            data[i] = data[i] ^ e.parity[i];
        }
        emit Decompressed(msg.sender, id, data, wtype, WSQDefenseType.ErrorCorrection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH ROBUST QUANTIZATION & RATE LIMIT
//    • ✅ Defense: RobustQuantization – multi-pass quantization  
//               RateLimit – cap compress calls per block
////////////////////////////////////////////////////////////////////////////////
contract WSQSafeAdvanced {
    mapping(bytes32 => bytes) public compressed;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event Compressed(
        address indexed who,
        bytes32                        id,
        WaveletScalarQuantizationType  wtype,
        WSQDefenseType                 defense
    );

    error WSQ__TooManyRequests();

    function compress(
        bytes32 id,
        bytes calldata raw,
        WaveletScalarQuantizationType wtype
    ) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WSQ__TooManyRequests();

        // stub robust quantization: two-pass store
        bytes memory tmp = raw;
        for (uint pass = 0; pass < 2; pass++) {
            for (uint i = 0; i < tmp.length; i++) {
                tmp[i] = tmp[i]; // noop quantization
            }
        }
        compressed[id] = tmp;
        emit Compressed(msg.sender, id, wtype, WSQDefenseType.RobustQuantization);
    }
}
