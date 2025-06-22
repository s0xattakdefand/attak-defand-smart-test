// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DatagramSuite.sol
/// @notice On‑chain analogues of “Datagram” messaging patterns:
///   Types: Unicast, Multicast, Broadcast, Fragment  
///   AttackTypes: Spoofing, Flooding, FragmentationAttack, Sniffing  
///   DefenseTypes: ChecksumValidation, RateLimit, AuthenticateSender, ReassemblyCheck  

enum DatagramType           { Unicast, Multicast, Broadcast, Fragment }
enum DatagramAttackType     { Spoofing, Flooding, FragmentationAttack, Sniffing }
enum DatagramDefenseType    { ChecksumValidation, RateLimit, AuthenticateSender, ReassemblyCheck }

error DG__BadChecksum();
error DG__TooMany();
error DG__NotAllowed();
error DG__BadReassembly();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DATAGRAM SENDER
//
//    • sends any payload to any address with no integrity or limits
//    • Attack: Spoofing, Sniffing, Flooding
////////////////////////////////////////////////////////////////////////////////
contract DatagramVuln {
    event Sent(
        address indexed from,
        address indexed to,
        DatagramType   dtype,
        bytes          payload,
        DatagramAttackType attack
    );

    function send(address to, DatagramType dtype, bytes calldata payload) external {
        emit Sent(msg.sender, to, dtype, payload, DatagramAttackType.Spoofing);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • floods and spoofs datagrams
////////////////////////////////////////////////////////////////////////////////
contract Attack_Datagram {
    DatagramVuln public target;
    constructor(DatagramVuln _t) { target = _t; }

    function flood(address to, DatagramType dtype, bytes calldata payload, uint count) external {
        for (uint i = 0; i < count; i++) {
            target.send(to, dtype, payload);
        }
    }

    function spoof(address victim, DatagramType dtype, bytes calldata payload) external {
        // pretend to be victim by calling target.send from this contract
        target.send(victim, dtype, payload);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE DATAGRAM WITH CHECKSUM VALIDATION
//
//    • Defense: ChecksumValidation – require checksum match (first 4 bytes)
////////////////////////////////////////////////////////////////////////////////
contract DatagramSafeChecksum {
    event Sent(
        address indexed from,
        address indexed to,
        DatagramType      dtype,
        bytes             payload,
        DatagramDefenseType defense
    );

    function send(address to, DatagramType dtype, bytes calldata payload, bytes4 checksum) external {
        // simple stub: compute keccak256 and compare first 4 bytes
        bytes4 computed = bytes4(keccak256(payload));
        if (computed != checksum) revert DG__BadChecksum();
        emit Sent(msg.sender, to, dtype, payload, DatagramDefenseType.ChecksumValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE DATAGRAM WITH RATE‑LIMIT
//
//    • Defense: RateLimit – cap sends per block per sender
////////////////////////////////////////////////////////////////////////////////
contract DatagramSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 20;

    event Sent(
        address indexed from,
        address indexed to,
        DatagramType      dtype,
        bytes             payload,
        DatagramDefenseType defense
    );

    function send(address to, DatagramType dtype, bytes calldata payload) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert DG__TooMany();
        emit Sent(msg.sender, to, dtype, payload, DatagramDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE DATAGRAM WITH SENDER AUTHENTICATION
//
//    • Defense: AuthenticateSender – only whitelisted senders
////////////////////////////////////////////////////////////////////////////////
contract DatagramSafeAuth {
    mapping(address => bool) public allowed;
    address public owner;

    event Sent(
        address indexed from,
        address indexed to,
        DatagramType      dtype,
        bytes             payload,
        DatagramDefenseType defense
    );

    error DG__NotAllowed();

    constructor() {
        owner = msg.sender;
    }

    function setAllowed(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        allowed[who] = ok;
    }

    function send(address to, DatagramType dtype, bytes calldata payload) external {
        if (!allowed[msg.sender]) revert DG__NotAllowed();
        emit Sent(msg.sender, to, dtype, payload, DatagramDefenseType.AuthenticateSender);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 6) SAFE DATAGRAM WITH REASSEMBLY CHECK
//
//    • Defense: ReassemblyCheck – require ordered fragments with sequence ID
////////////////////////////////////////////////////////////////////////////////
contract DatagramSafeReassembly {
    struct Fragment { uint16 seq; bytes data; }
    mapping(bytes32 => uint16) public lastSeq;

    event Sent(
        address indexed from,
        address indexed to,
        bytes32          packetId,
        uint16           seq,
        bytes            data,
        DatagramDefenseType defense
    );

    error DG__BadReassembly();

    function sendFragment(
        address to,
        bytes32 packetId,
        uint16 seq,
        bytes calldata data
    ) external {
        uint16 prev = lastSeq[packetId];
        // require fragments in sequence order
        if (seq != prev + 1) revert DG__BadReassembly();
        lastSeq[packetId] = seq;
        emit Sent(msg.sender, to, packetId, seq, data, DatagramDefenseType.ReassemblyCheck);
    }
}
