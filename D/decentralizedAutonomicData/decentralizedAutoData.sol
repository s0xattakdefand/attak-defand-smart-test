// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DecentralizedAutonomicDataSuite.sol
/// @notice On‐chain analogues of “Decentralized Autonomic Data” management patterns:
///   Types: SensorNetwork, EdgeStorage, SelfHealingRepo, AutonomousIndexer  
///   AttackTypes: DataPoisoning, SybilInjection, ReplayAttack, Partitioning  
///   DefenseTypes: AccessControl, DataValidation, RateLimit, MultiSig, SignatureValidation

enum DADType              { SensorNetwork, EdgeStorage, SelfHealingRepo, AutonomousIndexer }
enum DADAttackType        { DataPoisoning, SybilInjection, ReplayAttack, Partitioning }
enum DADDefenseType       { AccessControl, DataValidation, RateLimit, MultiSig, SignatureValidation }

error DAD__NotAuthorized();
error DAD__InvalidData();
error DAD__TooManyRequests();
error DAD__InvalidSignature();
error DAD__AlreadyApproved();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE AUTONOMIC DATA STORE
//    • ❌ no checks: anyone may write or read → DataPoisoning
////////////////////////////////////////////////////////////////////////////////
contract DADVuln {
    mapping(bytes32 => bytes) public repo;

    event DataWritten(
        address indexed who,
        bytes32           key,
        DADType           dtype,
        DADAttackType     attack
    );
    event DataRead(
        address indexed who,
        bytes32           key,
        DADType           dtype,
        DADAttackType     attack
    );

    function writeData(bytes32 key, bytes calldata data, DADType dtype) external {
        repo[key] = data;
        emit DataWritten(msg.sender, key, dtype, DADAttackType.DataPoisoning);
    }
    function readData(bytes32 key, DADType dtype) external view returns (bytes memory) {
        emit DataRead(msg.sender, key, dtype, DADAttackType.Partitioning);
        return repo[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates poisoning, sybil, replay, partition
////////////////////////////////////////////////////////////////////////////////
contract Attack_DAD {
    DADVuln public target;
    bytes32 public lastKey;
    bytes   public lastData;

    constructor(DADVuln _t) {
        target = _t;
    }

    function poison(bytes32 key, bytes calldata fake) external {
        target.writeData(key, fake, DADType.SelfHealingRepo);
        lastKey  = key;
        lastData = fake;
    }
    function sybilInject(bytes32 key, bytes calldata data) external {
        // many virtual identities write
        for (uint i = 0; i < 3; i++) {
            target.writeData(keccak256(abi.encodePacked(key,i)), data, DADType.SensorNetwork);
        }
    }
    function replay() external {
        target.writeData(lastKey, lastData, DADType.EdgeStorage);
    }
    function partition(bytes32 key) external view returns (bytes memory) {
        // simulate partition read
        return target.readData(key, DADType.AutonomousIndexer);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may write
////////////////////////////////////////////////////////////////////////////////
contract DADSafeAccess {
    mapping(bytes32 => bytes) public repo;
    address public owner;

    event DataWritten(
        address indexed who,
        bytes32           key,
        DADType           dtype,
        DADDefenseType    defense
    );
    event DataRead(
        address indexed who,
        bytes32           key,
        DADType           dtype,
        DADDefenseType    defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DAD__NotAuthorized();
        _;
    }

    function writeData(bytes32 key, bytes calldata data, DADType dtype) external onlyOwner {
        repo[key] = data;
        emit DataWritten(msg.sender, key, dtype, DADDefenseType.AccessControl);
    }
    function readData(bytes32 key, DADType dtype) external view onlyOwner returns (bytes memory) {
        emit DataRead(msg.sender, key, dtype, DADDefenseType.AccessControl);
        return repo[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH DATA VALIDATION & RATE LIMIT
//    • ✅ Defense: DataValidation – nonempty & size check  
//               RateLimit      – cap writes per block
////////////////////////////////////////////////////////////////////////////////
contract DADSafeValidate {
    mapping(bytes32 => bytes) public repo;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public writesInBlock;
    uint256 public constant MAX_WRITES = 3;

    event DataWritten(
        address indexed who,
        bytes32           key,
        DADType           dtype,
        DADDefenseType    defense
    );
    error DAD__InvalidData();
    error DAD__TooManyRequests();

    function writeData(bytes32 key, bytes calldata data, DADType dtype) external {
        // data validation: nonzero length and ≤1KB
        if (data.length == 0 || data.length > 1024) revert DAD__InvalidData();

        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            writesInBlock[msg.sender] = 0;
        }
        writesInBlock[msg.sender]++;
        if (writesInBlock[msg.sender] > MAX_WRITES) revert DAD__TooManyRequests();

        repo[key] = data;
        emit DataWritten(msg.sender, key, dtype, DADDefenseType.DataValidation);
    }

    function readData(bytes32 key, DADType dtype) external view returns (bytes memory) {
        return repo[key];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH MULTISIG & SIGNATURE VALIDATION
//    • ✅ Defense: MultiSig              – require N owner approvals  
//               SignatureValidation     – require signer approval
////////////////////////////////////////////////////////////////////////////////
contract DADSafeAdvanced {
    mapping(bytes32 => bytes) public repo;
    address[] public owners;
    uint256 public required;
    mapping(uint256 => mapping(address => bool)) public approved;
    mapping(uint256 => uint256) public approvalCount;
    uint256 public proposalCount;
    address public signer;

    event ProposalCreated(
        uint256 indexed proposalId,
        address indexed proposer,
        bytes32           key,
        DADType           dtype,
        DADDefenseType    defense
    );
    event Approved(
        uint256 indexed proposalId,
        address indexed owner,
        uint256           count,
        DADDefenseType    defense
    );
    event DataWritten(
        uint256 indexed proposalId,
        bytes32           key,
        DADDefenseType    defense
    );

    error DAD__NotAuthorized();
    error DAD__AlreadyApproved();
    error DAD__InsufficientApprovals();
    error DAD__InvalidSignature();

    struct Proposal {
        bytes32 key;
        bytes   data;
        DADType dtype;
        bool    executed;
    }
    mapping(uint256 => Proposal) public proposals;

    constructor(address[] memory _owners, uint256 _required, address _signer) {
        require(_required <= _owners.length, "invalid required");
        owners = _owners;
        required = _required;
        signer = _signer;
    }

    function proposeWrite(
        bytes32 key,
        bytes calldata data,
        DADType dtype,
        bytes calldata sig
    ) external returns (uint256) {
        // signature validation over (key||data||dtype)
        bytes32 h = keccak256(abi.encodePacked(key, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DAD__InvalidSignature();

        proposals[proposalCount] = Proposal(key, data, dtype, false);
        emit ProposalCreated(proposalCount, msg.sender, key, dtype, DADDefenseType.SignatureValidation);
        return proposalCount++;
    }

    function approveWrite(uint256 pid) external {
        // only owners
        bool isOwner;
        for (uint i; i < owners.length; i++) {
            if (owners[i] == msg.sender) { isOwner = true; break; }
        }
        if (!isOwner) revert DAD__NotAuthorized();
        if (approved[pid][msg.sender]) revert DAD__AlreadyApproved();

        approved[pid][msg.sender] = true;
        approvalCount[pid]++;
        emit Approved(pid, msg.sender, approvalCount[pid], DADDefenseType.MultiSig);

        if (approvalCount[pid] >= required && !proposals[pid].executed) {
            Proposal storage p = proposals[pid];
            p.executed = true;
            repo[p.key] = p.data;
            emit DataWritten(pid, p.key, DADDefenseType.MultiSig);
        }
    }

    function readData(bytes32 key, DADType dtype) external view returns (bytes memory) {
        return repo[key];
    }
}
