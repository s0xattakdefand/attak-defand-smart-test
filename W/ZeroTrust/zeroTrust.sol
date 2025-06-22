// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ZeroTrustSuite.sol
/// @notice On-chain analogues of “Zero Trust” security models:
///   Types: PerimeterBased, IdentityBased, ContextAware, Microsegmentation  
///   AttackTypes: Phishing, LateralMovement, PrivilegeEscalation, CredentialStuffing  
///   DefenseTypes: MultiFactor, Microsegmentation, ContinuousMonitoring, Encryption  

enum ZeroTrustType           { PerimeterBased, IdentityBased, ContextAware, Microsegmentation }
enum ZeroTrustAttackType     { Phishing, LateralMovement, PrivilegeEscalation, CredentialStuffing }
enum ZeroTrustDefenseType    { MultiFactor, Microsegmentation, ContinuousMonitoring, Encryption }

error ZT__Unauthorized();
error ZT__NoMFA();
error ZT__SegmentViolation();
error ZT__TooManyRequests();
error ZT__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ACCESS CONTROLLER
//
//    • ❌ No verification: anyone may access any resource → Phishing, LateralMovement
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustVuln {
    event AccessAttempt(
        address indexed who,
        bytes32            resource,
        ZeroTrustType      ztype,
        ZeroTrustAttackType attack
    );

    function access(bytes32 resource, ZeroTrustType ztype) external {
        emit AccessAttempt(msg.sender, resource, ztype, ZeroTrustAttackType.LateralMovement);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates credential stuffing & replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_ZeroTrust {
    ZeroTrustVuln public target;
    bytes32 public lastResource;

    constructor(ZeroTrustVuln _t) { target = _t; }

    function credentialStuff(bytes32 resource) external {
        target.access(resource, ZeroTrustType.IdentityBased);
    }

    function capture(bytes32 resource) external {
        lastResource = resource;
    }

    function replay() external {
        target.access(lastResource, ZeroTrustType.PerimeterBased);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH MULTI-FACTOR AUTHENTICATION
//
//    • ✅ Defense: MultiFactor – require OTP before access
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustSafeMFA {
    mapping(address => bytes32) public otpToken;
    mapping(address => bool)    private mfaPassed;

    event OTPIssued(address indexed who, bytes32 token, ZeroTrustDefenseType defense);
    event AccessGranted(
        address indexed who,
        bytes32            resource,
        ZeroTrustType      ztype,
        ZeroTrustDefenseType defense
    );

    error ZT__NoMFA();

    /// admin issues OTP off-chain
    function issueOTP(address user, bytes32 token) external {
        otpToken[user] = token;
        emit OTPIssued(user, token, ZeroTrustDefenseType.MultiFactor);
    }

    function verifyOTP(bytes32 token) external {
        require(otpToken[msg.sender] == token, "bad OTP");
        mfaPassed[msg.sender] = true;
        delete otpToken[msg.sender];
    }

    function access(bytes32 resource, ZeroTrustType ztype) external {
        if (!mfaPassed[msg.sender]) revert ZT__NoMFA();
        mfaPassed[msg.sender] = false;
        emit AccessGranted(msg.sender, resource, ztype, ZeroTrustDefenseType.MultiFactor);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH MICROSEGMENTATION
//
//    • ✅ Defense: Microsegmentation – resources grouped, access only within segment
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustSafeSegmentation {
    mapping(address => bytes32) public segmentOf;
    mapping(bytes32 => mapping(address => bool)) public allowedInSegment;

    event AccessGranted(
        address indexed who,
        bytes32            resource,
        ZeroTrustType      ztype,
        ZeroTrustDefenseType defense
    );

    error ZT__SegmentViolation();

    /// admin assigns user to a segment
    function assignSegment(address user, bytes32 segment) external {
        segmentOf[user] = segment;
    }

    /// admin allows user in resource segment
    function allowInSegment(bytes32 segment, address user, bool ok) external {
        allowedInSegment[segment][user] = ok;
    }

    function access(bytes32 resource, ZeroTrustType ztype, bytes32 resourceSegment) external {
        if (!allowedInSegment[resourceSegment][msg.sender]) revert ZT__SegmentViolation();
        emit AccessGranted(msg.sender, resource, ztype, ZeroTrustDefenseType.Microsegmentation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH CONTINUOUS MONITORING & ENCRYPTION
//
//    • ✅ Defense: ContinuousMonitoring – log every access and alert anomalies  
//               Encryption – require signed request for integrity
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustSafeAdvanced {
    address public signer;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 10;

    event AccessGranted(
        address indexed who,
        bytes32            resource,
        ZeroTrustType      ztype,
        ZeroTrustDefenseType defense
    );
    event AnomalyDetected(
        address indexed who,
        bytes32            resource,
        string             reason,
        ZeroTrustDefenseType defense
    );

    error ZT__TooManyRequests();
    error ZT__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function access(
        bytes32 resource,
        ZeroTrustType ztype,
        bytes calldata sig
    ) external {
        // rate-limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) {
            emit AnomalyDetected(msg.sender, resource, "rate limit exceeded", ZeroTrustDefenseType.ContinuousMonitoring);
            revert ZT__TooManyRequests();
        }

        // verify signature over (msg.sender||resource||ztype)
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, resource, ztype));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) {
            emit AnomalyDetected(msg.sender, resource, "invalid signature", ZeroTrustDefenseType.ContinuousMonitoring);
            revert ZT__InvalidSignature();
        }

        emit AccessGranted(msg.sender, resource, ztype, ZeroTrustDefenseType.Encryption);
    }
}
