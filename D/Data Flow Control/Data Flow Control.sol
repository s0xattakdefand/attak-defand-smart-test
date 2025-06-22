// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataFlowControlSecuritySuite.sol
/// @notice On‐chain analogues for “Data Flow Control” security patterns:
///   Types: Unrestricted, MandatoryAccess, RoleBased, Audited  
///   AttackTypes: UnauthorizedFlow, DataLeak, Tampering, Replay  
///   DefenseTypes: AccessControl, LabelEnforcement, RateLimit, AuditLogging, SignatureValidation

enum DataFlowType       { Unrestricted, MandatoryAccess, RoleBased, Audited }
enum DFAttackType       { UnauthorizedFlow, DataLeak, Tampering, Replay }
enum DFDefenseType      { AccessControl, LabelEnforcement, RateLimit, AuditLogging, SignatureValidation }

error DF__NotAuthorized();
error DF__InvalidInput();
error DF__TooManyRequests();
error DF__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE FLOW MANAGER
//    • ❌ no checks: anyone may send or receive → UnauthorizedFlow, DataLeak
////////////////////////////////////////////////////////////////////////////////
contract DataFlowVuln {
    mapping(uint256 => bytes)    public dataStore;
    mapping(uint256 => address)  public recipients;

    event DataSent(
        address indexed who,
        uint256           id,
        address           to,
        DataFlowType      dtype,
        DFAttackType      attack
    );
    event DataReceived(
        address indexed who,
        uint256           id,
        DataFlowType      dtype,
        DFAttackType      attack
    );

    function flowData(
        uint256 id,
        address to,
        bytes calldata data,
        DataFlowType dtype
    ) external {
        dataStore[id]   = data;
        recipients[id]  = to;
        emit DataSent(msg.sender, id, to, dtype, DFAttackType.UnauthorizedFlow);
    }

    function receiveData(uint256 id, DataFlowType dtype) external view returns (bytes memory) {
        emit DataReceived(msg.sender, id, dtype, DFAttackType.DataLeak);
        return dataStore[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized flows, leaks, tampering, replays
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataFlow {
    DataFlowVuln public target;
    uint256      public lastId;
    bytes        public lastData;

    constructor(DataFlowVuln _t) { target = _t; }

    function spoofFlow(uint256 id, address to, bytes calldata fake) external {
        target.flowData(id, to, fake, DataFlowType.Unrestricted);
        lastId   = id;
        lastData = fake;
    }

    function leakData(uint256 id) external {
        lastData = target.receiveData(id, DataFlowType.MandatoryAccess);
    }

    function tamperFlow(uint256 id, address to, bytes calldata fake) external {
        target.flowData(id, to, fake, DataFlowType.RoleBased);
    }

    function replayFlow() external {
        target.flowData(lastId, address(this), lastData, DataFlowType.Audited);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may flow or receive
////////////////////////////////////////////////////////////////////////////////
contract DataFlowSafeAccess {
    mapping(uint256 => bytes)   public dataStore;
    mapping(uint256 => address) public recipients;
    address public owner;

    event DataSent(
        address indexed who,
        uint256           id,
        address           to,
        DataFlowType      dtype,
        DFDefenseType     defense
    );
    event DataReceived(
        address indexed who,
        uint256           id,
        DataFlowType      dtype,
        DFDefenseType     defense
    );

    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DF__NotAuthorized();
        _;
    }

    function flowData(
        uint256 id,
        address to,
        bytes calldata data,
        DataFlowType dtype
    ) external onlyOwner {
        dataStore[id]  = data;
        recipients[id] = to;
        emit DataSent(msg.sender, id, to, dtype, DFDefenseType.AccessControl);
    }

    function receiveData(uint256 id, DataFlowType dtype)
        external view onlyOwner returns (bytes memory)
    {
        emit DataReceived(msg.sender, id, dtype, DFDefenseType.AccessControl);
        return dataStore[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: LabelEnforcement – require nonempty data  
//               RateLimit         – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataFlowSafeValidate {
    mapping(uint256 => bytes)   public dataStore;
    mapping(uint256 => address) public recipients;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 5;

    event DataSent(
        address indexed who,
        uint256           id,
        address           to,
        DataFlowType      dtype,
        DFDefenseType     defense
    );
    event DataReceived(
        address indexed who,
        uint256           id,
        DataFlowType      dtype,
        DFDefenseType     defense
    );

    error DF__InvalidInput();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender]  = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DF__TooManyRequests();
        _;
    }

    function flowData(
        uint256 id,
        address to,
        bytes calldata data,
        DataFlowType dtype
    ) external rateLimit {
        if (data.length == 0) revert DF__InvalidInput();
        dataStore[id]  = data;
        recipients[id] = to;
        emit DataSent(msg.sender, id, to, dtype, DFDefenseType.LabelEnforcement);
    }

    function receiveData(uint256 id, DataFlowType dtype)
        external view rateLimit returns (bytes memory)
    {
        emit DataReceived(msg.sender, id, dtype, DFDefenseType.RateLimit);
        return dataStore[id];
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require signed flows  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataFlowSafeAdvanced {
    mapping(uint256 => bytes)   public dataStore;
    mapping(uint256 => address) public recipients;
    address public signer;

    event DataSent(
        address indexed who,
        uint256           id,
        address           to,
        DataFlowType      dtype,
        DFDefenseType     defense
    );
    event DataReceived(
        address indexed who,
        uint256           id,
        DataFlowType      dtype,
        DFDefenseType     defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           id,
        DFDefenseType     defense
    );

    constructor(address _signer) { signer = _signer; }

    function flowData(
        uint256 id,
        address to,
        bytes calldata data,
        DataFlowType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("FLOW", msg.sender, id, to, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DF__InvalidSignature();

        dataStore[id]  = data;
        recipients[id] = to;
        emit DataSent(msg.sender, id, to, dtype, DFDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "flowData", id, DFDefenseType.AuditLogging);
    }

    function receiveData(
        uint256 id,
        DataFlowType dtype,
        bytes calldata sig
    ) external returns (bytes memory) {
        bytes32 h = keccak256(abi.encodePacked("RECEIVE", msg.sender, id, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DF__InvalidSignature();

        bytes memory d = dataStore[id];
        emit DataReceived(msg.sender, id, dtype, DFDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "receiveData", id, DFDefenseType.AuditLogging);
        return d;
    }
}
