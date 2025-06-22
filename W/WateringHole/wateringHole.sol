// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WateringHoleSuite.sol
/// @notice On‐chain analogues of “Watering Hole” compromise patterns:
///   Types: BrowserBased, PDFBased, MobileApp, IoTDevice  
///   AttackTypes: MalwareInjection, DriveByDownload, SpearPhishing, LateralMovement  
///   DefenseTypes: PatchManagement, ContentFiltering, NetworkSegmentation, EndpointDetection  

enum WateringHoleType          { BrowserBased, PDFBased, MobileApp, IoTDevice }
enum WateringHoleAttackType    { MalwareInjection, DriveByDownload, SpearPhishing, LateralMovement }
enum WateringHoleDefenseType   { PatchManagement, ContentFiltering, NetworkSegmentation, EndpointDetection }

error WH__NotAllowed();
error WH__UnsupportedContent();
error WH__Compromised();
error WH__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SITE
//
//    • ❌ no validation: any payload served → MalwareInjection
////////////////////////////////////////////////////////////////////////////////
contract WateringHoleVuln {
    mapping(WateringHoleType => string) public content;
    event Served(
        address indexed visitor,
        WateringHoleType    htype,
        string              data,
        WateringHoleAttackType attack
    );

    function hostContent(WateringHoleType htype, string calldata data) external {
        content[htype] = data;
    }

    function visit(WateringHoleType htype) external {
        // site serves whatever is hosted, attacker can inject
        emit Served(msg.sender, htype, content[htype], WateringHoleAttackType.MalwareInjection);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates compromise and lateral movement
////////////////////////////////////////////////////////////////////////////////
contract Attack_WateringHole {
    WateringHoleVuln public target;
    WateringHoleType public lastType;
    string           public lastPayload;

    constructor(WateringHoleVuln _t) { target = _t; }

    function compromise(WateringHoleType htype, string calldata payload) external {
        // attacker injects malicious payload
        target.hostContent(htype, payload);
        lastType = htype;
        lastPayload = payload;
    }

    function lure() external {
        // repeat visit to simulate drive‐by download
        target.visit(lastType);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH PATCH MANAGEMENT
//
//    • ✅ Defense: PatchManagement – require minimum version before visit
////////////////////////////////////////////////////////////////////////////////
contract WateringHoleSafePatch {
    mapping(WateringHoleType => string) public content;
    mapping(WateringHoleType => uint256) public minVersion;
    mapping(address => mapping(WateringHoleType => uint256)) public clientVersion;

    event Served(
        address indexed visitor,
        WateringHoleType    htype,
        string              data,
        WateringHoleDefenseType defense
    );
    error WH__Compromised();

    /// admin sets patched minimum version
    function setMinVersion(WateringHoleType htype, uint256 version) external {
        minVersion[htype] = version;
    }

    function hostContent(WateringHoleType htype, string calldata data, uint256 version) external {
        require(version >= minVersion[htype], "patch required");
        content[htype] = data;
    }

    function visit(WateringHoleType htype, uint256 clientVer) external {
        // require visitor up‐to‐date to avoid compromised content
        if (clientVer < minVersion[htype]) revert WH__Compromised();
        emit Served(msg.sender, htype, content[htype], WateringHoleDefenseType.PatchManagement);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH CONTENT FILTERING & RATE LIMIT
//
//    • ✅ Defense: ContentFiltering – strip dangerous scripts  
//               RateLimit – cap visits per block
////////////////////////////////////////////////////////////////////////////////
contract WateringHoleSafeFilter {
    mapping(WateringHoleType => string) public content;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public visitsInBlock;
    uint256 public constant MAX_VISITS = 5;

    event Served(
        address indexed visitor,
        WateringHoleType    htype,
        string              data,
        WateringHoleDefenseType defense
    );
    error WH__UnsupportedContent();
    error WH__TooManyRequests();

    function hostContent(WateringHoleType htype, string calldata data) external {
        content[htype] = data;
    }

    function _sanitize(string memory s) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        bytes memory out = new bytes(b.length);
        uint256 j;
        for (uint256 i; i < b.length; i++) {
            // drop '<' and "script"
            if (b[i] == "<" || (i+5 < b.length &&
                b[i]== "s" && b[i+1]=="c" && b[i+2]=="r" && b[i+3]=="i" && b[i+4]=="p" && b[i+5]=="t")) {
                continue;
            }
            out[j++] = b[i];
        }
        assembly { mstore(out, j) }
        return string(out);
    }

    function visit(WateringHoleType htype) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            visitsInBlock[msg.sender] = 0;
        }
        visitsInBlock[msg.sender]++;
        if (visitsInBlock[msg.sender] > MAX_VISITS) revert WH__TooManyRequests();

        string memory clean = _sanitize(content[htype]);
        if (bytes(clean).length == 0) revert WH__UnsupportedContent();
        emit Served(msg.sender, htype, clean, WateringHoleDefenseType.ContentFiltering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH NETWORK SEGMENTATION & ENDPOINT DETECTION
//
//    • ✅ Defense: NetworkSegmentation – only segmented subnets can serve  
//               EndpointDetection – detect anomalous visits
////////////////////////////////////////////////////////////////////////////////
contract WateringHoleSafeAdvanced {
    mapping(WateringHoleType => string) public content;
    mapping(address => bytes32) public segment;
    mapping(WateringHoleType => bytes32) public allowedSegment;
    mapping(address => uint256) public visitCount;
    event Served(
        address indexed visitor,
        WateringHoleType    htype,
        string              data,
        WateringHoleDefenseType defense
    );
    event Alert(
        address indexed visitor,
        string              reason,
        WateringHoleDefenseType defense
    );

    error WH__NotAllowed();
    error WH__AnomalyDetected();

    /// admin assigns segment for each host type
    function setAllowedSegment(WateringHoleType htype, bytes32 seg) external {
        allowedSegment[htype] = seg;
    }

    /// visitor must register segment (e.g. VPN/proxy group)
    function registerSegment(bytes32 seg) external {
        segment[msg.sender] = seg;
    }

    function hostContent(WateringHoleType htype, string calldata data) external {
        content[htype] = data;
    }

    function visit(WateringHoleType htype) external {
        // segmentation check
        if (segment[msg.sender] != allowedSegment[htype]) revert WH__NotAllowed();
        // anomaly detection: too many visits
        visitCount[msg.sender]++;
        if (visitCount[msg.sender] > 20) {
            emit Alert(msg.sender, "suspicious high visit rate", WateringHoleDefenseType.EndpointDetection);
            revert WH__AnomalyDetected();
        }
        emit Served(msg.sender, htype, content[htype], WateringHoleDefenseType.NetworkSegmentation);
    }
}
