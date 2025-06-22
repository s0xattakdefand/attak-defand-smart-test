// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthorizeIDSuite.sol
/// @notice On-chain analogues of “Authorize ID” patterns:
///   Types: ManualApproval, TokenBased, Biometric  
///   AttackTypes: UnauthorizedGrant, TokenReplay, Tampering  
///   DefenseTypes: OwnerCheck, SignatureValidation, TwoFactor  

enum AuthorizeIDType           { ManualApproval, TokenBased, Biometric }
enum AuthorizeIDAttackType     { UnauthorizedGrant, TokenReplay, Tampering }
enum AuthorizeIDDefenseType    { OwnerCheck, SignatureValidation, TwoFactor }

error AID__NotOwner();
error AID__InvalidSignature();
error AID__No2FA();
error AID__Replay();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE AUTHORIZER
//
//    • ❌ no controls: anyone may authorize any ID → UnauthorizedGrant
////////////////////////////////////////////////////////////////////////////////
contract AuthorizeIDVuln {
    mapping(bytes32 => address) public authorized;  // idHash → user

    event IDAuthorized(
        address indexed by,
        bytes32            idHash,
        address            user,
        AuthorizeIDType    atype,
        AuthorizeIDAttackType attack
    );

    function authorize(bytes32 idHash, address user, AuthorizeIDType atype) external {
        authorized[idHash] = user;
        emit IDAuthorized(msg.sender, idHash, user, atype, AuthorizeIDAttackType.UnauthorizedGrant);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates forging or replaying authorizations
////////////////////////////////////////////////////////////////////////////////
contract Attack_AuthorizeID {
    AuthorizeIDVuln public target;
    bytes32 public lastId;
    address public lastUser;

    constructor(AuthorizeIDVuln _t) {
        target = _t;
    }

    function stealGrant(bytes32 idHash, address victim) external {
        target.authorize(idHash, victim, AuthorizeIDType.ManualApproval);
    }

    function captureAndReplay(bytes32 idHash, address user) external {
        lastId = idHash;
        lastUser = user;
        target.authorize(idHash, user, AuthorizeIDType.ManualApproval);
    }

    function replay() external {
        target.authorize(lastId, lastUser, AuthorizeIDType.ManualApproval);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE OWNER-CONTROLLED AUTHORIZATION
//
//    • ✅ Defense: OwnerCheck – only contract owner may authorize
////////////////////////////////////////////////////////////////////////////////
contract AuthorizeIDSafeOwner {
    address public owner;
    mapping(bytes32 => address) public authorized;

    event IDAuthorized(
        address indexed by,
        bytes32            idHash,
        address            user,
        AuthorizeIDType    atype,
        AuthorizeIDDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    function authorize(bytes32 idHash, address user, AuthorizeIDType atype) external {
        if (msg.sender != owner) revert AID__NotOwner();
        authorized[idHash] = user;
        emit IDAuthorized(msg.sender, idHash, user, atype, AuthorizeIDDefenseType.OwnerCheck);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE SIGNATURE-BASED AUTHORIZATION
//
//    • ✅ Defense: SignatureValidation – require owner’s signed approval
////////////////////////////////////////////////////////////////////////////////
contract AuthorizeIDSafeSig {
    address public approver;
    mapping(bytes32 => address) public authorized;
    mapping(bytes32 => bool)    public usedSig;

    event IDAuthorized(
        address indexed by,
        bytes32            idHash,
        address            user,
        AuthorizeIDType    atype,
        AuthorizeIDDefenseType defense
    );

    error AID__Replay();

    constructor(address _approver) {
        approver = _approver;
    }

    /// require signature over (idHash||user||nonce)
    function authorize(
        bytes32 idHash,
        address user,
        uint256 nonce,
        bytes calldata sig,
        AuthorizeIDType atype
    ) external {
        bytes32 key = keccak256(abi.encodePacked(idHash, user, nonce));
        if (usedSig[key]) revert AID__Replay();
        usedSig[key] = true;

        bytes32 msgHash = keccak256(abi.encodePacked(key));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != approver) revert AID__InvalidSignature();

        authorized[idHash] = user;
        emit IDAuthorized(msg.sender, idHash, user, atype, AuthorizeIDDefenseType.SignatureValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED TWO-FACTOR AUTHORIZATION
//
//    • ✅ Defense: TwoFactor – require OTP + owner approval
////////////////////////////////////////////////////////////////////////////////
contract AuthorizeIDSafe2FA {
    address public owner;
    mapping(address => bool) public otpPassed;
    mapping(bytes32 => address) public authorized;

    event OTPVerified(address indexed who, AuthorizeIDDefenseType defense);
    event IDAuthorized(
        address indexed by,
        bytes32            idHash,
        address            user,
        AuthorizeIDType    atype,
        AuthorizeIDDefenseType defense
    );

    error AID__No2FA();
    error AID__NotOwner();

    constructor() {
        owner = msg.sender;
    }

    /// stub: user obtains OTP off-chain and presents it
    function verifyOTP(bytes32 otp) external {
        // simplest check: otp == keccak256(user||blockhash)
        bytes32 expected = keccak256(abi.encodePacked(msg.sender, blockhash(block.number - 1)));
        require(otp == expected, "invalid OTP");
        otpPassed[msg.sender] = true;
        emit OTPVerified(msg.sender, AuthorizeIDDefenseType.TwoFactor);
    }

    function authorize(bytes32 idHash, address user, AuthorizeIDType atype) external {
        if (!otpPassed[msg.sender]) revert AID__No2FA();
        if (msg.sender != owner) revert AID__NotOwner();
        otpPassed[msg.sender] = false;

        authorized[idHash] = user;
        emit IDAuthorized(msg.sender, idHash, user, atype, AuthorizeIDDefenseType.TwoFactor);
    }
}
