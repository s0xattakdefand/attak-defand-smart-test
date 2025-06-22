// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WhoisSuite.sol
/// @notice On‑chain analogues of “WHOIS” lookup patterns:
///   Types: DomainQuery, ReverseQuery, BulkQuery, ZoneTransfer  
///   AttackTypes: SpoofResponse, FloodQuery, ZoneTransferAttack, DataLeak  
///   DefenseTypes: ValidateResponse, RateLimit, AuthenticatedQuery, NoZoneTransfer  

enum WhoisType          { DomainQuery, ReverseQuery, BulkQuery, ZoneTransfer }
enum WhoisAttackType    { SpoofResponse, FloodQuery, ZoneTransferAttack, DataLeak }
enum WhoisDefenseType   { ValidateResponse, RateLimit, AuthenticatedQuery, NoZoneTransfer }

error WHO__NotAllowed();
error WHO__TooManyRequests();
error WHO__ZoneTransferForbidden();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WHOIS LOOKUP
//
//   • anyone may query any domain or perform zone transfers  
//   • Attack: SpoofResponse
////////////////////////////////////////////////////////////////////////
contract WhoisVuln {
    event WhoisResult(
        address indexed requester,
        WhoisType      qType,
        string         query,
        string         result,
        WhoisAttackType attack
    );

    /// ❌ no access control, logs raw result
    function query(WhoisType qType, string calldata query) external {
        // stub raw whois data
        string memory res = string(abi.encodePacked("WHOIS data for ", query));
        emit WhoisResult(msg.sender, qType, query, res, WhoisAttackType.SpoofResponse);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//   • FloodQuery + ZoneTransferAttack
////////////////////////////////////////////////////////////////////////
contract Attack_Whois {
    WhoisVuln public target;
    constructor(WhoisVuln _t) { target = _t; }

    /// attacker floods with many queries
    function flood(address to, string[] calldata domains) external {
        for (uint i; i < domains.length; i++) {
            target.query(WhoisType.DomainQuery, domains[i]);
        }
    }

    /// attacker abuses zone transfer
    function zoneTransfer(string calldata zone) external {
        target.query(WhoisType.ZoneTransfer, zone);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE: AUTHENTICATED + NO ZONE TRANSFER
//
//   • only whitelisted callers may query  
//   • zone transfers forbidden
////////////////////////////////////////////////////////////////////////
contract WhoisSafeAuth {
    mapping(address => bool) public allowed;
    address public owner;
    event WhoisResult(
        address indexed requester,
        WhoisType      qType,
        string         query,
        string         result,
        WhoisDefenseType defense
    );

    constructor() { owner = msg.sender; }

    function setAllowed(address who, bool ok) external {
        if (msg.sender != owner) revert WHO__NotAllowed();
        allowed[who] = ok;
    }

    function query(WhoisType qType, string calldata query) external {
        if (!allowed[msg.sender]) revert WHO__NotAllowed();
        if (qType == WhoisType.ZoneTransfer) revert WHO__ZoneTransferForbidden();
        string memory res = string(abi.encodePacked("WHOIS data for ", query));
        emit WhoisResult(msg.sender, qType, query, res, WhoisDefenseType.AuthenticatedQuery);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE: RATE‑LIMIT + RESPONSE VALIDATION
//
//   • cap queries per block per caller  
//   • require non‑empty result
////////////////////////////////////////////////////////////////////////
contract WhoisSafeRateLimitValidate {
    mapping(address => uint) public lastBlock;
    mapping(address => uint) public countInBlock;
    uint public constant MAX_PER_BLOCK = 5;

    event WhoisResult(
        address indexed requester,
        WhoisType      qType,
        string         query,
        string         result,
        WhoisDefenseType defense
    );

    function query(WhoisType qType, string calldata query) external {
        if (qType == WhoisType.ZoneTransfer) revert WHO__ZoneTransferForbidden();
        // rate‑limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert WHO__TooManyRequests();
        // stub lookup
        string memory res = string(abi.encodePacked("WHOIS data for ", query));
        // validate response non‑empty
        require(bytes(res).length > 0, "empty response");
        emit WhoisResult(msg.sender, qType, query, res, WhoisDefenseType.RateLimit);
        emit WhoisResult(msg.sender, qType, query, res, WhoisDefenseType.ValidateResponse);
    }
}
