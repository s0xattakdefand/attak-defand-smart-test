// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DestinationAddressSuite.sol
/// @notice On‐chain analogues of “Destination Address” routing patterns:
///   Types: IPv4, IPv6, Hostname, MAC  
///   AttackTypes: Spoofing, Hijacking, Filtering, Tampering  
///   DefenseTypes: AccessControl, FormatValidation, ACLFiltering, RateLimit, SignatureValidation

enum DestAddrType            { IPv4, IPv6, Hostname, MAC }
enum DestAddrAttackType      { Spoofing, Hijacking, Filtering, Tampering }
enum DestAddrDefenseType     { AccessControl, FormatValidation, ACLFiltering, RateLimit, SignatureValidation }

error DA__NotAuthorized();
error DA__InvalidFormat();
error DA__Blocked();
error DA__TooManyRequests();
error DA__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ROUTER
//    • ❌ no checks: anyone may set any destination → Spoofing, Hijacking
////////////////////////////////////////////////////////////////////////////////
contract DestinationAddressVuln {
    mapping(uint256 => string) public destinations;

    event DestinationSet(
        address            who,
        uint256            routeId,
        DestAddrType       atype,
        DestAddrAttackType attack
    );

    function setDestination(
        uint256 routeId,
        string calldata dest,
        DestAddrType atype
    ) external {
        destinations[routeId] = dest;
        emit DestinationSet(msg.sender, routeId, atype, DestAddrAttackType.Spoofing);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates spoofing, hijacking, tampering, DOS via filtering
////////////////////////////////////////////////////////////////////////////////
contract Attack_DestinationAddress {
    DestinationAddressVuln public target;
    uint256 public lastRoute;
    string  public lastDest;
    DestAddrType public lastType;

    constructor(DestinationAddressVuln _t) {
        target = _t;
    }

    function spoof(uint256 routeId, string calldata fake) external {
        target.setDestination(routeId, fake, DestAddrType.IPv4);
        lastRoute = routeId;
        lastDest  = fake;
        lastType  = DestAddrType.IPv4;
    }

    function hijack(uint256 routeId, string calldata fake) external {
        target.setDestination(routeId, fake, DestAddrType.Hostname);
    }

    function tamper() external {
        target.setDestination(lastRoute, lastDest, lastType);
    }

    function flood(uint256 baseId, uint count) external {
        for (uint i = 0; i < count; i++) {
            target.setDestination(baseId + i, "0.0.0.0", DestAddrType.IPv4);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may set
////////////////////////////////////////////////////////////////////////////////
contract DestinationAddressSafeAccess {
    mapping(uint256 => string) public destinations;
    address public owner;

    event DestinationSet(
        address            who,
        uint256            routeId,
        DestAddrType       atype,
        DestAddrDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert DA__NotAuthorized();
        _;
    }

    function setDestination(
        uint256 routeId,
        string calldata dest,
        DestAddrType atype
    ) external onlyOwner {
        destinations[routeId] = dest;
        emit DestinationSet(msg.sender, routeId, atype, DestAddrDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH FORMAT VALIDATION & ACL FILTERING & RATE LIMIT
//    • ✅ Defense: FormatValidation – require non‐empty, basic length check  
//               ACLFiltering      – block blacklisted prefixes  
//               RateLimit         – cap sets per block
////////////////////////////////////////////////////////////////////////////////
contract DestinationAddressSafeValidate {
    mapping(uint256 => string)        public destinations;
    mapping(string => bool)           public blacklist;
    mapping(address => uint256)       public lastBlock;
    mapping(address => uint256)       public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event DestinationSet(
        address            who,
        uint256            routeId,
        DestAddrType       atype,
        DestAddrDefenseType defense
    );

    error DA__InvalidFormat();
    error DA__Blocked();
    error DA__TooManyRequests();

    function setBlacklist(string calldata prefix, bool blocked) external {
        // stub: admin only in production
        blacklist[prefix] = blocked;
    }

    function _validateFormat(string memory s) internal pure {
        bytes memory b = bytes(s);
        if (b.length == 0 || b.length > 100) revert DA__InvalidFormat();
    }

    function setDestination(
        uint256 routeId,
        string calldata dest,
        DestAddrType atype
    ) external {
        // rate‐limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert DA__TooManyRequests();

        _validateFormat(dest);

        // simple ACL filtering: block any exact match
        if (blacklist[dest]) revert DA__Blocked();

        destinations[routeId] = dest;
        emit DestinationSet(msg.sender, routeId, atype, DestAddrDefenseType.ACLFiltering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & RATE LIMIT
//    • ✅ Defense: SignatureValidation – require admin signature over params  
//               RateLimit           – cap signed updates per block
////////////////////////////////////////////////////////////////////////////////
contract DestinationAddressSafeAdvanced {
    mapping(uint256 => string)  public destinations;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    address public signer;
    uint256 public constant MAX_CALLS = 3;

    event DestinationSet(
        address            who,
        uint256            routeId,
        DestAddrType       atype,
        DestAddrDefenseType defense
    );

    error DA__TooManyRequests();
    error DA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function setDestination(
        uint256 routeId,
        string calldata dest,
        DestAddrType atype,
        bytes calldata sig
    ) external {
        // rate‐limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert DA__TooManyRequests();

        // verify signature over (routeId||dest||atype)
        bytes32 h = keccak256(abi.encodePacked(routeId, dest, atype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert DA__InvalidSignature();

        destinations[routeId] = dest;
        emit DestinationSet(msg.sender, routeId, atype, DestAddrDefenseType.SignatureValidation);
    }
}
