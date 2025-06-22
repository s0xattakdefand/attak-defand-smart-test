// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataCuratorSecuritySuite.sol
/// @notice On‐chain analogues for “Data Curator” security patterns:
///   Types: Individual, Consortium, Automated, Decentralized  
///   AttackTypes: UnauthorizedPublish, DataPoisoning, ReplayPublish, FloodPublish  
///   DefenseTypes: AccessControl, Validation, RateLimit, SignatureValidation, AuditLogging

enum DCType               { Individual, Consortium, Automated, Decentralized }
enum DCAttackType         { UnauthorizedPublish, DataPoisoning, ReplayPublish, FloodPublish }
enum DCDefenseType        { AccessControl, Validation, RateLimit, SignatureValidation, AuditLogging }

error DC__NotAuthorized();
error DC__InvalidInput();
error DC__TooManyRequests();
error DC__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CURATOR
//    • ❌ no checks: anyone may publish or update dataset → UnauthorizedPublish/DataPoisoning
////////////////////////////////////////////////////////////////////////////////
contract DataCuratorVuln {
    mapping(uint256 => string) public datasets;

    event DatasetPublished(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCAttackType      attack
    );
    event DatasetUpdated(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCAttackType      attack
    );

    function publish(uint256 id, string calldata data, DCType dtype) external {
        datasets[id] = data;
        emit DatasetPublished(msg.sender, id, dtype, DCAttackType.UnauthorizedPublish);
    }

    function update(uint256 id, string calldata data, DCType dtype) external {
        datasets[id] = data;
        emit DatasetUpdated(msg.sender, id, dtype, DCAttackType.DataPoisoning);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates unauthorized publish, poisoning, replay, flood
////////////////////////////////////////////////////////////////////////////////
contract Attack_DataCurator {
    DataCuratorVuln public target;
    uint256 public lastId;
    string  public lastData;

    constructor(DataCuratorVuln _t) {
        target = _t;
    }

    function spoofPublish(uint256 id, string calldata fake) external {
        target.publish(id, fake, DCType.Individual);
        lastId   = id;
        lastData = fake;
    }

    function poison(uint256 id, string calldata fake) external {
        target.update(id, fake, DCType.Consortium);
    }

    function replayPublish() external {
        target.publish(lastId, lastData, DCType.Automated);
    }

    function floodPublish(uint256 id, uint256 times) external {
        for (uint i = 0; i < times; i++) {
            target.publish(id, "flood", DCType.Decentralized);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may publish/update
////////////////////////////////////////////////////////////////////////////////
contract DataCuratorSafeAccess {
    mapping(uint256 => string) public datasets;
    address public owner;

    event DatasetPublished(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCDefenseType     defense
    );
    event DatasetUpdated(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCDefenseType     defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert DC__NotAuthorized();
        _;
    }

    function publish(uint256 id, string calldata data, DCType dtype) external onlyOwner {
        datasets[id] = data;
        emit DatasetPublished(msg.sender, id, dtype, DCDefenseType.AccessControl);
    }

    function update(uint256 id, string calldata data, DCType dtype) external onlyOwner {
        datasets[id] = data;
        emit DatasetUpdated(msg.sender, id, dtype, DCDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH VALIDATION & RATE LIMIT
//    • ✅ Defense: Validation – require nonempty data  
//               RateLimit   – cap ops per block
////////////////////////////////////////////////////////////////////////////////
contract DataCuratorSafeValidate {
    mapping(uint256 => string) public datasets;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public opsInBlock;
    uint256 public constant MAX_OPS = 3;

    event DatasetPublished(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCDefenseType     defense
    );
    event DatasetUpdated(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCDefenseType     defense
    );

    error DC__InvalidInput();
    error DC__TooManyRequests();

    modifier rateLimit() {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]   = block.number;
            opsInBlock[msg.sender] = 0;
        }
        opsInBlock[msg.sender]++;
        if (opsInBlock[msg.sender] > MAX_OPS) revert DC__TooManyRequests();
        _;
    }

    function publish(uint256 id, string calldata data, DCType dtype) external rateLimit {
        if (bytes(data).length == 0) revert DC__InvalidInput();
        datasets[id] = data;
        emit DatasetPublished(msg.sender, id, dtype, DCDefenseType.Validation);
    }

    function update(uint256 id, string calldata data, DCType dtype) external rateLimit {
        if (bytes(data).length == 0) revert DC__InvalidInput();
        datasets[id] = data;
        emit DatasetUpdated(msg.sender, id, dtype, DCDefenseType.Validation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require curator‐signed ops  
//               AuditLogging      – record each action
////////////////////////////////////////////////////////////////////////////////
contract DataCuratorSafeAdvanced {
    mapping(uint256 => string) public datasets;
    address public signer;

    event DatasetPublished(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCDefenseType     defense
    );
    event DatasetUpdated(
        address indexed who,
        uint256           id,
        DCType            dtype,
        DCDefenseType     defense
    );
    event AuditLog(
        address indexed who,
        string            action,
        uint256           id,
        DCDefenseType     defense
    );

    error DC__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function publish(
        uint256 id,
        string calldata data,
        DCType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("PUBLISH", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DC__InvalidSignature();

        datasets[id] = data;
        emit DatasetPublished(msg.sender, id, dtype, DCDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "publish", id, DCDefenseType.AuditLogging);
    }

    function update(
        uint256 id,
        string calldata data,
        DCType dtype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("UPDATE", msg.sender, id, data, dtype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DC__InvalidSignature();

        datasets[id] = data;
        emit DatasetUpdated(msg.sender, id, dtype, DCDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "update", id, DCDefenseType.AuditLogging);
    }
}
