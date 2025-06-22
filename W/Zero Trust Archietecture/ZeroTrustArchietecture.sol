// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ZeroTrustArchitectureSuite.sol
/// @notice On-chain analogues of “Zero Trust Architecture” patterns:
///   Types: DeviceCentric, UserCentric, DataCentric, NetworkCentric  
///   AttackTypes: Phishing, LateralMovement, PrivilegeEscalation, CredentialStuffing  
///   DefenseTypes: MultiFactor, Microsegmentation, ContinuousMonitoring, Encryption  

enum ZeroTrustArchitectureType      { DeviceCentric, UserCentric, DataCentric, NetworkCentric }
enum ZeroTrustArchitectureAttackType{ Phishing, LateralMovement, PrivilegeEscalation, CredentialStuffing }
enum ZeroTrustArchitectureDefenseType{ MultiFactor, Microsegmentation, ContinuousMonitoring, Encryption }

error ZTA__Unauthorized();
error ZTA__NoMFA();
error ZTA__SegmentViolation();
error ZTA__TooManyRequests();
error ZTA__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE ARCHITECTURE
//    • ❌ no verification: any caller may access any resource → Phishing, LateralMovement
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustArchVuln {
    event AccessAttempt(
        address indexed who,
        bytes32            resource,
        ZeroTrustArchitectureType atype,
        ZeroTrustArchitectureAttackType attack
    );

    function access(bytes32 resource, ZeroTrustArchitectureType atype) external {
        // no checks
        emit AccessAttempt(msg.sender, resource, atype, ZeroTrustArchitectureAttackType.LateralMovement);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates credential stuffing & replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_ZeroTrustArch {
    ZeroTrustArchVuln public target;
    bytes32 public lastResource;

    constructor(ZeroTrustArchVuln _t) { target = _t; }

    function credentialStuff(bytes32 resource) external {
        target.access(resource, ZeroTrustArchitectureType.UserCentric);
    }

    function capture(bytes32 resource) external {
        lastResource = resource;
    }

    function replay() external {
        target.access(lastResource, ZeroTrustArchitectureType.DeviceCentric);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH MULTI-FACTOR AUTHENTICATION
//    • ✅ Defense: MultiFactor – require OTP before access
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustArchSafeMFA {
    mapping(address => bytes32) public otpToken;
    mapping(address => bool)    private mfaPassed;

    event OTPIssued(address indexed who, bytes32 token, ZeroTrustArchitectureDefenseType defense);
    event AccessGranted(
        address indexed who,
        bytes32            resource,
        ZeroTrustArchitectureType atype,
        ZeroTrustArchitectureDefenseType defense
    );

    error ZTA__NoMFA();

    /// admin issues OTP off-chain
    function issueOTP(address user, bytes32 token) external {
        otpToken[user] = token;
        emit OTPIssued(user, token, ZeroTrustArchitectureDefenseType.MultiFactor);
    }

    function verifyOTP(bytes32 token) external {
        require(otpToken[msg.sender] == token, "bad OTP");
        mfaPassed[msg.sender] = true;
        delete otpToken[msg.sender];
    }

    function access(bytes32 resource, ZeroTrustArchitectureType atype) external {
        if (!mfaPassed[msg.sender]) revert ZTA__NoMFA();
        mfaPassed[msg.sender] = false;
        emit AccessGranted(msg.sender, resource, atype, ZeroTrustArchitectureDefenseType.MultiFactor);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH MICROSEGMENTATION
//    • ✅ Defense: Microsegmentation – enforce segment‐based access
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustArchSafeMicroseg {
    mapping(address => bytes32) public segmentOf;
    mapping(bytes32 => mapping(address => bool)) public allowedInSegment;

    event AccessGranted(
        address indexed who,
        bytes32            resource,
        ZeroTrustArchitectureType atype,
        ZeroTrustArchitectureDefenseType defense
    );

    error ZTA__SegmentViolation();

    /// admin assigns user to a segment
    function assignSegment(address user, bytes32 segment) external {
        segmentOf[user] = segment;
    }

    /// admin allows user in resource segment
    function allowInSegment(bytes32 segment, address user, bool ok) external {
        allowedInSegment[segment][user] = ok;
    }

    function access(bytes32 resource, ZeroTrustArchitectureType atype, bytes32 resourceSegment) external {
        if (!allowedInSegment[resourceSegment][msg.sender]) revert ZTA__SegmentViolation();
        emit AccessGranted(msg.sender, resource, atype, ZeroTrustArchitectureDefenseType.Microsegmentation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH CONTINUOUS MONITORING & ENCRYPTION
//    • ✅ Defense: ContinuousMonitoring – log every access and alert anomalies  
//               Encryption – require signed request for integrity
////////////////////////////////////////////////////////////////////////////////
contract ZeroTrustArchSafeAdvanced {
    address public signer;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 10;

    event AccessGranted(
        address indexed who,
        bytes32            resource,
        ZeroTrustArchitectureType atype,
        ZeroTrustArchitectureDefenseType defense
    );
    event AnomalyDetected(
        address indexed who,
        bytes32            resource,
        string             reason,
        ZeroTrustArchitectureDefenseType defense
    );

    error ZTA__TooManyRequests();
    error ZTA__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function access(
        bytes32 resource,
        ZeroTrustArchitectureType atype,
        bytes calldata sig
    ) external {
        // rate-limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) {
            emit AnomalyDetected(msg.sender, resource, "rate limit exceeded", ZeroTrustArchitectureDefenseType.ContinuousMonitoring);
            revert ZTA__TooManyRequests();
        }

        // verify signature over (sender||resource||atype)
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, resource, atype));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) {
            emit AnomalyDetected(msg.sender, resource, "invalid signature", ZeroTrustArchitectureDefenseType.ContinuousMonitoring);
            revert ZTA__InvalidSignature();
        }

        emit AccessGranted(msg.sender, resource, atype, ZeroTrustArchitectureDefenseType.Encryption);
    }
}
