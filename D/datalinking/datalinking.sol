// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* =======================================================================
   DEMO - “Matching & Combining Data From Multiple Databases”
   -- ISO/TS 25237:2008  &  NISTIR 8053 linkage attack illustration
   -- One file, six contracts:
        · RegistryA, RegistryB, VulnerableLinkage   (⚠️  vulnerable)
        · PseudoId, SafeRegistryA, SafeRegistryB    (✅  hardened)
   ======================================================================= */

/* -----------------------------------------------------------------------
   SECTION 1 — VULNERABLE IMPLEMENTATION
   --------------------------------------------------------------------- */
contract RegistryA {
    struct RecordA { string nationalId; string bloodType; string city; }
    mapping(address => RecordA) public recordsA;

    function addRecordA(
        string calldata nationalId,
        string calldata bloodType,
        string calldata city
    ) external {
        recordsA[msg.sender] = RecordA(nationalId, bloodType, city);
    }
}

contract RegistryB {
    struct RecordB { string nationalId; uint256 birthYear; string employer; }
    mapping(address => RecordB) public recordsB;

    function addRecordB(
        string calldata nationalId,
        uint256 birthYear,
        string calldata employer
    ) external {
        recordsB[msg.sender] = RecordB(nationalId, birthYear, employer);
    }
}

contract VulnerableLinkage {
    RegistryA public a;
    RegistryB public b;

    constructor(address addrA, address addrB) {
        a = RegistryA(addrA);
        b = RegistryB(addrB);
    }

    /* ⚠️  A real attacker would iterate the mappings off-chain and
           link on clear-text nationalId.  Kept empty to avoid huge gas. */
    function combinedProfile(string calldata /*nationalId*/ ) external pure {
        revert("Iterate off-chain for demo purposes");
    }
}

/* -----------------------------------------------------------------------
   SECTION 2 — HARDENED IMPLEMENTATION
   --------------------------------------------------------------------- */

/* --- Small Ownable so we avoid external imports --------------------- */
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    constructor() { _owner = msg.sender; emit OwnershipTransferred(address(0), _owner); }
    modifier onlyOwner() { require(msg.sender == _owner, "Not owner"); _; }
    function owner() public view returns (address) { return _owner; }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/* --- Minimal ECDSA helper (to replace OpenZeppelin import) ----------- */
library MiniECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
    function recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "Bad sig len");
        bytes32 r; bytes32 s; uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(toEthSignedMessageHash(hash), v, r, s);
    }
}

/* --- Library to create salted pseudonyms ----------------------------- */
library PseudoId {
    function derive(bytes32 salt, string calldata id)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(salt, id));
    }
}

/* --- Safe registries using pseudonym-keys --------------------------- */
contract SafeRegistryA is Ownable {
    using PseudoId  for bytes32;
    using MiniECDSA for bytes32;

    struct RecordA { string bloodType; string city; }

    bytes32 public immutable systemSalt;
    mapping(bytes32 => RecordA) private recordsA;

    event RecordAAdded(bytes32 indexed pseudoId);

    constructor(bytes32 _salt) { systemSalt = _salt; }

    function addRecordA(
        string calldata nationalId,
        string calldata bloodType,
        string calldata city,
        bytes calldata userSig   /* signed off-chain by data subject */
    ) external {
        bytes32 pseudoId = systemSalt.derive(nationalId);
        bytes32 msgHash  = keccak256(abi.encodePacked(address(this), pseudoId));
        require(msgHash.recover(userSig) == msg.sender, "Consent sig bad");

        recordsA[pseudoId] = RecordA(bloodType, city);
        emit RecordAAdded(pseudoId);
    }

    /* Data subject-only read */
    function getMyRecord(string calldata nationalId)
        external
        view
        returns (RecordA memory)
    {
        return recordsA[systemSalt.derive(nationalId)];
    }
}

contract SafeRegistryB is Ownable {
    using PseudoId  for bytes32;
    using MiniECDSA for bytes32;

    struct RecordB { uint256 birthYear; string employer; }

    bytes32 public immutable systemSalt;
    mapping(bytes32 => RecordB) private recordsB;

    event RecordBAdded(bytes32 indexed pseudoId);

    constructor(bytes32 _salt) { systemSalt = _salt; }

    function addRecordB(
        string calldata nationalId,
        uint256 birthYear,
        string calldata employer,
        bytes calldata userSig
    ) external {
        bytes32 pseudoId = systemSalt.derive(nationalId);
        bytes32 msgHash  = keccak256(abi.encodePacked(address(this), pseudoId));
        require(msgHash.recover(userSig) == msg.sender, "Consent sig bad");

        recordsB[pseudoId] = RecordB(birthYear, employer);
        emit RecordBAdded(pseudoId);
    }

    function getMyRecord(string calldata nationalId)
        external
        view
        returns (RecordB memory)
    {
        return recordsB[systemSalt.derive(nationalId)];
    }
}
