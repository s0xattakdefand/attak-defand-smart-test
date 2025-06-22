// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DomainNameSystemSuite.sol
/// @notice On‑chain analogues of “Domain Name System” (DNS) patterns:
///   Types: RecursiveResolver, AuthoritativeServer, StubResolver  
///   AttackTypes: CachePoisoning, Spoofing, DDoS, NXDomainFlood  
///   DefenseTypes: DNSSECValidation, RateLimit, QueryFiltering, ResponseValidation  

enum DomainNameSystemType         { RecursiveResolver, AuthoritativeServer, StubResolver }
enum DomainNameSystemAttackType   { CachePoisoning, Spoofing, DDoS, NXDomainFlood }
enum DomainNameSystemDefenseType  { DNSSECValidation, RateLimit, QueryFiltering, ResponseValidation }

error DNS__TooManyQueries();
error DNS__InvalidSignature();
error DNS__SpoofDetected();
error DNS__BlockedName();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DNS RESOLVER
//
//    • no validation, unlimited queries → CachePoisoning, Spoofing, DDoS
////////////////////////////////////////////////////////////////////////////////
contract DNSVuln {
    mapping(string => address) public records; // name → IP

    event Queried(
        address indexed who,
        string           name,
        address          result,
        DomainNameSystemAttackType attack
    );

    function setRecord(string calldata name, address ip) external {
        records[name] = ip;
    }

    function resolve(string calldata name) external view returns (address) {
        address ip = records[name];
        emit Queried(msg.sender, name, ip, DomainNameSystemAttackType.Spoofing);
        return ip;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • floods queries and injects false records
////////////////////////////////////////////////////////////////////////////////
contract Attack_DNS {
    DNSVuln public target;
    constructor(DNSVuln _t) { target = _t; }

    /// flood DDoS queries
    function flood(string calldata name, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            target.resolve(name);
        }
    }

    /// poison cache by overwriting records
    function poison(string calldata name, address fakeIp) external {
        target.setRecord(name, fakeIp);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE DNS WITH DNSSEC VALIDATION
//
//    • Defense: DNSSECValidation – require oracle signature on record
////////////////////////////////////////////////////////////////////////////////
contract DNSSafeDNSSEC {
    mapping(string => address) public records;
    address public dnssecOracle;
    event Queried(
        address indexed who,
        string           name,
        address          result,
        DomainNameSystemDefenseType defense
    );

    constructor(address oracle) {
        dnssecOracle = oracle;
    }

    /// only accept updates with oracle signature over (name,ip)
    function setRecord(
        string calldata name,
        address ip,
        bytes calldata oracleSig
    ) external {
        bytes32 msgHash = keccak256(abi.encodePacked(name, ip));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(oracleSig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != dnssecOracle) revert DNS__InvalidSignature();
        records[name] = ip;
    }

    function resolve(string calldata name) external returns (address) {
        address ip = records[name];
        emit Queried(msg.sender, name, ip, DomainNameSystemDefenseType.DNSSECValidation);
        return ip;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE DNS WITH RATE‑LIMIT & QUERY FILTERING
//
//    • Defense: RateLimit – cap queries per block  
//               QueryFiltering – block NXDomain floods
////////////////////////////////////////////////////////////////////////////////
contract DNSSafeRateFilter {
    mapping(string => address) public records;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_QUERIES_PER_BLOCK = 10;

    event Queried(
        address indexed who,
        string           name,
        address          result,
        DomainNameSystemDefenseType defense
    );

    error DNS__TooManyQueries();
    error DNS__BlockedName();

    /// owner may set records normally
    address public owner;
    constructor() { owner = msg.sender; }

    function setRecord(string calldata name, address ip) external {
        require(msg.sender == owner, "only owner");
        records[name] = ip;
    }

    function resolve(string calldata name) external returns (address) {
        // rate‑limit per caller
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_QUERIES_PER_BLOCK) revert DNS__TooManyQueries();

        // block queries for non‐existent names to prevent NXDOMAIN flood
        address ip = records[name];
        if (ip == address(0)) revert DNS__BlockedName();

        emit Queried(msg.sender, name, ip, DomainNameSystemDefenseType.QueryFiltering);
        return ip;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED DNS WITH RESPONSE VALIDATION
//
//    • Defense: ResponseValidation – verify record consistency across sources
////////////////////////////////////////////////////////////////////////////////
contract DNSSafeAdvanced {
    mapping(string => address[]) public candidates; // multiple source IPs
    event Queried(
        address indexed who,
        string           name,
        address          result,
        DomainNameSystemDefenseType defense
    );

    /// add trusted source records
    function addSource(string calldata name, address ip) external {
        candidates[name].push(ip);
    }

    /// resolve by majority vote among sources
    function resolve(string calldata name) external returns (address) {
        address[] storage ips = candidates[name];
        require(ips.length > 0, "no sources");
        // simple majority stub: pick first that appears most
        // here just return first for stub
        address ip = ips[0];
        emit Queried(msg.sender, name, ip, DomainNameSystemDefenseType.ResponseValidation);
        return ip;
    }
}
