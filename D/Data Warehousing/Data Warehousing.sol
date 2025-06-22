// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DataWarehousingSuite.sol
/// @notice On‑chain analogues of “Data Warehousing” patterns:
///   Types: ETL, OLAP, DataMart, StreamLoad  
///   AttackTypes: SchemaPoisoning, DataPoisoning, UnauthorizedQuery, OverflowAttack  
///   DefenseTypes: SchemaValidation, AccessControl, RateLimit, InputSanitization  

enum DataWarehousingType         { ETL, OLAP, DataMart, StreamLoad }
enum DataWarehousingAttackType   { SchemaPoisoning, DataPoisoning, UnauthorizedQuery, OverflowAttack }
enum DataWarehousingDefenseType  { SchemaValidation, AccessControl, RateLimit, InputSanitization }

error DW__BadSchema();
error DW__NotAuthorized();
error DW__TooManyLoads();
error DW__BadInput();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE INGESTION & QUERY
///
///    • no validation: any data may be loaded without schema checks  
///    • no access control on queries  
///    • Attack: SchemaPoisoning, UnauthorizedQuery  
///─────────────────────────────────────────────────────────────────────────────
contract DataWarehousingVuln {
    // warehouseId → array of raw records
    mapping(uint256 => bytes[]) public records;

    event DataLoaded(
        uint256 indexed warehouseId,
        bytes          data,
        DataWarehousingAttackType attack
    );
    event DataQueried(
        uint256 indexed warehouseId,
        bytes[]        result,
        DataWarehousingAttackType attack
    );

    /// ❌ load any blob, no schema validation
    function loadData(uint256 warehouseId, bytes calldata data) external {
        records[warehouseId].push(data);
        emit DataLoaded(warehouseId, data, DataWarehousingAttackType.SchemaPoisoning);
    }

    /// ❌ anyone may query entire store
    function queryData(uint256 warehouseId) external view returns (bytes[] memory) {
        emit DataQueried(warehouseId, records[warehouseId], DataWarehousingAttackType.UnauthorizedQuery);
        return records[warehouseId];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB
///
///    • floods poison records  
///    • then queries unauthorized  
///─────────────────────────────────────────────────────────────────────────────
contract Attack_DataWarehousing {
    DataWarehousingVuln public target;

    constructor(DataWarehousingVuln _t) {
        target = _t;
    }

    /// poison warehouse with bad entries
    function poison(uint256 warehouseId, bytes[] calldata payloads) external {
        for (uint i = 0; i < payloads.length; i++) {
            target.loadData(warehouseId, payloads[i]);
        }
    }

    /// extract all data
    function dump(uint256 warehouseId) external view returns (bytes[] memory) {
        return target.queryData(warehouseId);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE INGESTION WITH SCHEMA VALIDATION & ACCESS CONTROL
///
///    • Defense: only authorized loaders  
///               simple schema check (e.g. non‑empty, length limit)  
///─────────────────────────────────────────────────────────────────────────────
contract DataWarehousingSafe {
    mapping(uint256 => bytes[]) public records;
    mapping(address => bool)   public loaders;
    address public owner;

    event DataLoaded(
        uint256 indexed warehouseId,
        bytes          data,
        DataWarehousingDefenseType defense
    );
    event DataQueried(
        uint256 indexed warehouseId,
        bytes[]        result,
        DataWarehousingDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// owner manages authorized loaders
    function setLoader(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        loaders[who] = ok;
    }

    /// ✅ only authorized loaders & basic schema validation
    function loadData(uint256 warehouseId, bytes calldata data) external {
        if (!loaders[msg.sender]) revert DW__NotAuthorized();
        if (data.length == 0 || data.length > 1024) revert DW__BadSchema();
        records[warehouseId].push(data);
        emit DataLoaded(warehouseId, data, DataWarehousingDefenseType.SchemaValidation);
    }

    /// ✅ restrict queries to owner only
    function queryData(uint256 warehouseId) external view returns (bytes[] memory) {
        if (msg.sender != owner) revert DW__NotAuthorized();
        emit DataQueried(warehouseId, records[warehouseId], DataWarehousingDefenseType.AccessControl);
        return records[warehouseId];
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) ADVANCED SAFE WITH RATE‑LIMIT & INPUT SANITIZATION
///
///    • Defense: rate‑limit loads per block  
///               sanitize queries by filtering empty entries  
///─────────────────────────────────────────────────────────────────────────────
contract DataWarehousingSafeAdvanced {
    mapping(uint256 => bytes[]) public records;
    mapping(address => uint256) public lastLoadBlock;
    mapping(address => uint256) public loadsInBlock;
    address public owner;
    uint256 public constant MAX_LOADS_PER_BLOCK = 5;

    event DataLoaded(
        uint256 indexed warehouseId,
        bytes          data,
        DataWarehousingDefenseType defense
    );
    event DataQueried(
        uint256 indexed warehouseId,
        bytes[]        result,
        DataWarehousingDefenseType defense
    );

    error DW__TooManyLoads();

    constructor() {
        owner = msg.sender;
    }

    /// rate‑limited load & require non‑empty data
    function loadData(uint256 warehouseId, bytes calldata data) external {
        // only owner or authorized by owner
        require(msg.sender == owner, "only owner");

        // rate‑limit per block
        if (block.number != lastLoadBlock[msg.sender]) {
            lastLoadBlock[msg.sender] = block.number;
            loadsInBlock[msg.sender] = 0;
        }
        loadsInBlock[msg.sender]++;
        if (loadsInBlock[msg.sender] > MAX_LOADS_PER_BLOCK) revert DW__TooManyLoads();

        // sanitization: no empty or too‑large records
        if (data.length == 0 || data.length > 2048) revert DW__BadInput();

        records[warehouseId].push(data);
        emit DataLoaded(warehouseId, data, DataWarehousingDefenseType.RateLimit);
    }

    /// sanitize output: filter out zero‑length entries
    function queryData(uint256 warehouseId) external view returns (bytes[] memory) {
        bytes[] memory raw = records[warehouseId];
        uint count;
        for (uint i; i < raw.length; i++) {
            if (raw[i].length > 0) count++;
        }
        bytes[] memory filtered = new bytes[](count);
        uint idx;
        for (uint i; i < raw.length; i++) {
            if (raw[i].length > 0) {
                filtered[idx++] = raw[i];
            }
        }
        emit DataQueried(warehouseId, filtered, DataWarehousingDefenseType.InputSanitization);
        return filtered;
    }
}
