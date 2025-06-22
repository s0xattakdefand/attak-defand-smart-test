// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ConvertChannelsSuite.sol
/// @notice On‑chain analogues of “Convert Channels” patterns:
///   Types: AudioToData, DataToAudio, VideoToAudio, AnalogToDigital  
///   AttackTypes: SpoofConversion, DataLoss, FormatMismatch, Overflow  
///   DefenseTypes: FormatValidation, Checksum, RateLimit, AuthControl  

enum ConvertChannelType        { AudioToData, DataToAudio, VideoToAudio, AnalogToDigital }
enum ConvertChannelAttackType  { SpoofConversion, DataLoss, FormatMismatch, Overflow }
enum ConvertChannelDefenseType { FormatValidation, Checksum, RateLimit, AuthControl }

error CC__InvalidFormat();
error CC__TooMany();
error CC__NotAllowed();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CONVERSION (no validation, unlimited use)
//    • Vulnerable: accepts any input for any conversion type
//    • Attack: SpoofConversion, DataLoss
////////////////////////////////////////////////////////////////////////////////
contract ConvertChannelsVuln {
    event Converted(
        address indexed who,
        ConvertChannelType ctype,
        bytes              input,
        bytes              output,
        ConvertChannelAttackType attack
    );

    /// ❌ no validation: returns input as output and logs generic attack
    function convert(ConvertChannelType ctype, bytes calldata input) external returns (bytes memory) {
        bytes memory out = input;
        emit Converted(msg.sender, ctype, input, out, ConvertChannelAttackType.SpoofConversion);
        return out;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates passing malformed data to cause FormatMismatch
////////////////////////////////////////////////////////////////////////////////
contract Attack_ConvertChannels {
    ConvertChannelsVuln public target;
    constructor(ConvertChannelsVuln _t) { target = _t; }

    /// attacker submits bogus payload to spoof conversion
    function spoof(ConvertChannelType ctype) external {
        // e.g. empty payload or too-short header
        target.convert(ctype, "");
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE CONVERSION WITH FORMAT VALIDATION & CHECKSUM
//    • Defense: FormatValidation (non‑empty, reasonable size)
//               Checksum (emit hash of output)
////////////////////////////////////////////////////////////////////////////////
contract ConvertChannelsSafeValidate {
    event Converted(
        address indexed who,
        ConvertChannelType ctype,
        bytes              output,
        bytes32            checksum,
        ConvertChannelDefenseType defense
    );
    error CC__InvalidFormat();

    function convert(ConvertChannelType ctype, bytes calldata input) external returns (bytes memory) {
        // ✅ basic format validation: non‑empty and <= 1 KB
        if (input.length == 0 || input.length > 1024) revert CC__InvalidFormat();
        // stub “conversion”: here we just echo input
        bytes memory out = input;
        // emit checksum of output
        bytes32 cs = keccak256(out);
        emit Converted(msg.sender, ctype, out, cs, ConvertChannelDefenseType.FormatValidation);
        return out;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE ADVANCED WITH RATE‑LIMIT & OWNERSHIP CONTROL
//    • Defense: RateLimit (cap per block)  
//               AuthControl (only owner may convert certain types)
////////////////////////////////////////////////////////////////////////////////
contract ConvertChannelsSafeAdvanced {
    address public owner;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    event Converted(
        address indexed who,
        ConvertChannelType ctype,
        bytes              output,
        ConvertChannelDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// only owner may convert VideoToAudio and AnalogToDigital
    modifier allowedType(ConvertChannelType ctype) {
        if ((ctype == ConvertChannelType.VideoToAudio || ctype == ConvertChannelType.AnalogToDigital)
            && msg.sender != owner) {
            revert CC__NotAllowed();
        }
        _;
    }

    function convert(ConvertChannelType ctype, bytes calldata input)
        external
        allowedType(ctype)
        returns (bytes memory)
    {
        // rate‑limit per caller per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert CC__TooMany();

        // stub “conversion”
        bytes memory out = input;
        emit Converted(msg.sender, ctype, out, ConvertChannelDefenseType.RateLimit);
        return out;
    }
}
