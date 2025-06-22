// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WebSecurityApplianceSuite.sol
/// @notice On-chain analogues of “Web Security Appliance” patterns:
///   Types: Hardware, Virtual, Cloud, Inline  
///   AttackTypes: MalwareInjection, Bypass, ProtocolAnomaly, DDoS  
///   DefenseTypes: TrafficInspection, SignatureUpdate, SSLDecryption, RateLimit  

enum WebSecurityApplianceType        { Hardware, Virtual, Cloud, Inline }
enum WebSecurityApplianceAttackType  { MalwareInjection, Bypass, ProtocolAnomaly, DDoS }
enum WebSecurityApplianceDefenseType { TrafficInspection, SignatureUpdate, SSLDecryption, RateLimit }

error WSA__Blocked();
error WSA__NoSigDB();
error WSA__TooManyRequests();
error WSA__SSLRequired();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE APPLIANCE
//
//    • ❌ no inspection or controls: any request is forwarded → ProtocolAnomaly
////////////////////////////////////////////////////////////////////////////////
contract WebSecurityApplianceVuln {
    event Request(
        address indexed client,
        string            url,
        bytes             payload,
        WebSecurityApplianceType       atype,
        WebSecurityApplianceAttackType attack
    );

    function handleRequest(
        string calldata url,
        bytes calldata payload,
        WebSecurityApplianceType atype
    ) external {
        // no filtering or analysis
        emit Request(msg.sender, url, payload, atype, WebSecurityApplianceAttackType.ProtocolAnomaly);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates malware injection, bypass, and DDoS
////////////////////////////////////////////////////////////////////////////////
contract Attack_WebSecurityAppliance {
    WebSecurityApplianceVuln public target;

    constructor(WebSecurityApplianceVuln _t) {
        target = _t;
    }

    function injectMalware(string calldata url, bytes calldata payload) external {
        target.handleRequest(url, payload, WebSecurityApplianceType.Inline);
    }

    function bypass(string calldata url) external {
        target.handleRequest(url, "", WebSecurityApplianceType.Hardware);
    }

    function flood(string calldata url, uint count) external {
        for (uint i = 0; i < count; i++) {
            target.handleRequest(url, "", WebSecurityApplianceType.Virtual);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH TRAFFIC INSPECTION
//
//    • ✅ Defense: TrafficInspection – drop payloads with “malware” marker
////////////////////////////////////////////////////////////////////////////////
contract WebSecurityApplianceSafeInspect {
    event Request(
        address indexed client,
        string            url,
        WebSecurityApplianceDefenseType defense
    );
    error WSA__Blocked();

    function handleRequest(string calldata url, bytes calldata payload) external {
        // simple inspection: reject if payload contains "malware"
        bytes memory p = payload;
        for (uint i = 0; i + 6 < p.length; i++) {
            if (
                p[i] == "m" && p[i+1] == "a" && p[i+2] == "l" &&
                p[i+3] == "w" && p[i+4] == "a" && p[i+5] == "r" && p[i+6] == "e"
            ) revert WSA__Blocked();
        }
        emit Request(msg.sender, url, WebSecurityApplianceDefenseType.TrafficInspection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH SIGNATURE UPDATE
//
//    • ✅ Defense: SignatureUpdate – require DB version ≥ minVersion
////////////////////////////////////////////////////////////////////////////////
contract WebSecurityApplianceSafeSignature {
    uint256 public sigDBVersion;
    uint256 public minVersion;
    event Request(
        address indexed client,
        string            url,
        WebSecurityApplianceDefenseType defense
    );
    error WSA__NoSigDB();

    constructor(uint256 _minVersion) {
        minVersion = _minVersion;
    }

    function updateSigDB(uint256 version) external {
        sigDBVersion = version;
    }

    function handleRequest(string calldata url, bytes calldata, WebSecurityApplianceType) external {
        if (sigDBVersion < minVersion) revert WSA__NoSigDB();
        emit Request(msg.sender, url, WebSecurityApplianceDefenseType.SignatureUpdate);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SSL DECRYPTION & RATE LIMIT
//
//    • ✅ Defense: SSLDecryption – require SSL flag  
//               RateLimit – cap requests per block per client
////////////////////////////////////////////////////////////////////////////////
contract WebSecurityApplianceSafeAdvanced {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 10;

    event Request(
        address indexed client,
        string            url,
        WebSecurityApplianceDefenseType defense
    );
    error WSA__TooManyRequests();
    error WSA__SSLRequired();

    function handleRequest(
        string calldata url,
        bytes calldata payload,
        WebSecurityApplianceType atype,
        bool ssl
    ) external {
        if (!ssl) revert WSA__SSLRequired();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert WSA__TooManyRequests();
        // assume decryption of payload here
        emit Request(msg.sender, url, WebSecurityApplianceDefenseType.SSLDecryption);
    }
}
