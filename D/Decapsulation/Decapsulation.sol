// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DecapsulationSuite.sol
/// @notice On‑chain analogues of “Decapsulation” patterns:
///   Types: IPinIP, GRE, VXLAN, MPLS  
///   AttackTypes: PacketSmuggling, HeaderOverflow, TLVSpoof  
///   DefenseTypes: HeaderValidation, LengthCheck, AuthenticatedEncap  

enum DecapsulationType         { IPinIP, GRE, VXLAN, MPLS }
enum DecapsulationAttackType   { PacketSmuggling, HeaderOverflow, TLVSpoof }
enum DecapsulationDefenseType  { HeaderValidation, LengthCheck, AuthenticatedEncap }

error DCAP__BadHeader();
error DCAP__BadLength();
error DCAP__NotAuthenticated();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE DECAPSULATION
///
///    • strips outer header without validation → smuggling & overflow
///─────────────────────────────────────────────────────────────────────────────
contract DecapsulationVuln {
    event Decapsulated(
        address indexed who,
        DecapsulationType dtype,
        bytes           inner,
        DecapsulationAttackType attack
    );

    function decapsulate(DecapsulationType dtype, bytes calldata pkt) external {
        // ❌ no header check: assume first 20 bytes are header
        bytes memory inner = pkt[20:];
        emit Decapsulated(msg.sender, dtype, inner, DecapsulationAttackType.PacketSmuggling);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • crafts malformed packet to overflow or slip bytes
///─────────────────────────────────────────────────────────────────────────────
contract Attack_Decapsulation {
    DecapsulationVuln public target;
    constructor(DecapsulationVuln _t) { target = _t; }

    function smuggle(DecapsulationType dtype, bytes calldata payload) external {
        // attacker crafts pkt shorter than headerLen to underflow
        bytes memory pkt = abi.encodePacked(payload);
        target.decapsulate(dtype, pkt);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE DECAPSULATION WITH HEADER & LENGTH CHECK
///
///    • Defense: validate header bits & total length
///─────────────────────────────────────────────────────────────────────────────
contract DecapsulationSafe {
    event Decapsulated(
        address indexed who,
        DecapsulationType dtype,
        bytes           inner,
        DecapsulationDefenseType defense
    );

    function decapsulate(DecapsulationType dtype, bytes calldata pkt) external {
        // require at least minimal header length
        if (pkt.length < 20) revert DCAP__BadLength();
        // simple header validation stub: first byte must be 0x45 (IPv4 IHL=5)
        if (pkt[0] != 0x45) revert DCAP__BadHeader();
        // strip header
        bytes memory inner = pkt[20:];
        emit Decapsulated(msg.sender, dtype, inner, DecapsulationDefenseType.HeaderValidation);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) ADVANCED SAFE WITH AUTH & RATE‑LIMIT
///
///    • Defense: authenticated callers & cap ops per block  
///─────────────────────────────────────────────────────────────────────────────
contract DecapsulationSafeAdvanced {
    mapping(address => bool)        public allowed;
    mapping(address => uint256)     public lastBlock;
    mapping(address => uint256)     public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 10;

    event Decapsulated(
        address indexed who,
        DecapsulationType dtype,
        bytes           inner,
        DecapsulationDefenseType defense
    );

    error DCAP__NotAllowed();
    error DCAP__TooMany();

    modifier onlyAllowed() {
        if (!allowed[msg.sender]) revert DCAP__NotAllowed();
        _;
    }

    function setAllowed(address who, bool ok) external {
        // for simplicity, contract deployer is owner
        require(msg.sender == address(this) || msg.sender == tx.origin, "only owner");
        allowed[who] = ok;
    }

    function decapsulate(DecapsulationType dtype, bytes calldata pkt)
        external
        onlyAllowed
    {
        // rate‑limit per caller per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DCAP__TooMany();

        // header & length checks
        if (pkt.length < 20) revert DCAP__BadLength();
        if (pkt[0] != 0x45) revert DCAP__BadHeader();

        // strip header
        bytes memory inner = pkt[20:];
        emit Decapsulated(msg.sender, dtype, inner, DecapsulationDefenseType.AuthenticatedEncap);
    }
}
