// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CRCSuite.sol
/// @notice On‑chain analogues of “Cyclic Redundancy Check” (CRC) patterns:
///   Types: CRC8, CRC16, CRC32  
///   AttackTypes: BitFlipAttack, PolynomialCollision, ReplayAttack  
///   DefenseTypes: ChecksumValidation, SaltedCRC, DualCRC, RateLimit  

enum CRCType               { CRC8, CRC16, CRC32 }
enum CRCAttackType         { BitFlipAttack, PolynomialCollision, ReplayAttack }
enum CRCDefenseType        { ChecksumValidation, SaltedCRC, DualCRC, RateLimit }

error CRC__BadChecksum();
error CRC__NoSalt();
error CRC__MismatchCRC();
error CRC__TooMany();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CRC CALCULATOR
//
//    • computes CRC with no salt or replay protection  
//    • Attack: BitFlipAttack, ReplayAttack
////////////////////////////////////////////////////////////////////////////////
contract CRCVuln {
    event Checked(
        address indexed who,
        CRCType    kind,
        bytes      data,
        uint32     crc,
        CRCAttackType attack
    );

    /// ❌ naive CRC32 stub: just keccak truncated
    function computeAndCheck(CRCType kind, bytes calldata data, uint32 expected) external {
        uint32 crc = uint32(uint256(keccak256(data)));
        // no validation: even if mismatch, considered ok
        emit Checked(msg.sender, kind, data, crc, CRCAttackType.BitFlipAttack);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • tries to flip bits or replay old data
////////////////////////////////////////////////////////////////////////////////
contract Attack_CRC {
    CRCVuln public target;
    constructor(CRCVuln _t) { target = _t; }

    /// attacker replays an old data+crc pair
    function replay(bytes calldata data, uint32 crc, CRCType kind) external {
        target.computeAndCheck(kind, data, crc);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE CRC VALIDATION
//
//    • Defense: ChecksumValidation – require computed == expected
////////////////////////////////////////////////////////////////////////////////
contract CRCSafeValidate {
    event Checked(
        address indexed who,
        CRCType    kind,
        bytes      data,
        uint32     crc,
        CRCDefenseType defense
    );
    error CRC__BadChecksum();

    function computeAndCheck(CRCType kind, bytes calldata data, uint32 expected) external {
        uint32 crc = uint32(uint256(keccak256(data)));
        if (crc != expected) revert CRC__BadChecksum();
        emit Checked(msg.sender, kind, data, crc, CRCDefenseType.ChecksumValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE SALTED & DUAL CRC
//
//    • Defense: SaltedCRC – include salt in checksum  
//               DualCRC – combine two CRC variants
////////////////////////////////////////////////////////////////////////////////
contract CRCSafeSaltedDual {
    event Checked(
        address indexed who,
        CRCType    kind,
        bytes      data,
        uint32     saltedCrc,
        uint32     altCrc,
        CRCDefenseType defense
    );
    error CRC__NoSalt();
    error CRC__MismatchCRC();

    /// salted CRC: keccak(data||salt) truncated
    function computeAndCheck(
        CRCType kind,
        bytes calldata data,
        uint32 expectedSalted,
        bytes32 salt
    ) external {
        if (salt == bytes32(0)) revert CRC__NoSalt();
        bytes memory blob = abi.encodePacked(data, salt);
        uint32 saltedCrc = uint32(uint256(keccak256(blob)));
        if (saltedCrc != expectedSalted) revert CRC__MismatchCRC();
        // dual CRC: simple alternative CRC16 stub via truncated keccak
        uint32 altCrc = uint32(uint256(keccak256(abi.encodePacked(data, uint16(0xFFFF))))) & 0xFFFF;
        emit Checked(msg.sender, kind, data, saltedCrc, altCrc, CRCDefenseType.SaltedCRC);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE RATE‑LIMITED CRC SERVICE
//
//    • Defense: RateLimit – cap checks per block per user
////////////////////////////////////////////////////////////////////////////////
contract CRCSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_CHECKS_PER_BLOCK = 10;

    event Checked(
        address indexed who,
        CRCType    kind,
        bytes      data,
        uint32     crc,
        CRCDefenseType defense
    );
    error CRC__TooMany();

    function computeAndCheck(CRCType kind, bytes calldata data, uint32 expected) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_CHECKS_PER_BLOCK) revert CRC__TooMany();

        uint32 crc = uint32(uint256(keccak256(data)));
        require(crc == expected, "CRC mismatch");
        emit Checked(msg.sender, kind, data, crc, CRCDefenseType.RateLimit);
    }
}
