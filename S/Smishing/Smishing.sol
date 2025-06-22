// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

///─────────────────────────────────────────────────────────────────────────────
///                            ECDSA HELPER LIBRARY
///─────────────────────────────────────────────────────────────────────────────
library ECDSALib {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0,mload(add(sig,96)))
        }
        address a = ecrecover(h, v, r, s);
        require(a != address(0), "ECDSA: invalid");
        return a;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) SMS‑OTP AUTHENTICATION (Smishable OTP)
///─────────────────────────────────────────────────────────────────────────────
error SmsAuth__BadOTP();
error SmsAuth__Expired();
error SmsAuth__Replayed();

// ❌ Vulnerable: OTP stored on‑chain, no replay or signature
contract SmsOtpAuthVuln {
    mapping(address=>uint256) public otp;
    mapping(address=>uint256) public expiry;

    /// Off‑chain SMS service sets the OTP and its expiry
    function setOtp(uint256 code, uint256 validTill) external {
        otp[msg.sender]    = code;
        expiry[msg.sender] = validTill;
    }

    /// User submits code; phishable by Smishing
    function authenticate(uint256 code) external view returns (bool) {
        require(block.timestamp <= expiry[msg.sender], "SmsAuthVuln: expired");
        return otp[msg.sender] == code;
    }
}

/// Attack: simply calls `authenticate()` with any phished code
contract Attack_SmsOtpPhish {
    SmsOtpAuthVuln public target;
    constructor(SmsOtpAuthVuln _t) { target = _t; }
    function phish(uint256 code) external view returns (bool) {
        return target.authenticate(code);
    }
}

// ✅ Safe: require off‑chain SMS service to EIP‑712‑sign (user,otp,nonce,expiry)
contract SmsOtpAuthSafe {
    using ECDSALib for bytes32;

    address public immutable smsService;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("SmsOTP(address user,uint256 otp,uint256 nonce,uint256 expiry)");

    mapping(uint256=>bool) public usedNonce;

    error SmsAuthSafe__BadSig();
    error SmsAuthSafe__Expired();
    error SmsAuthSafe__Replayed();

    event Authenticated(address indexed user, uint256 otp);

    constructor(address _smsService) {
        smsService = _smsService;
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SmsOtpAuthSafe"),
                block.chainid,
                address(this)
            )
        );
    }

    /// Caller provides OTP + nonce + expiry + SMS‑signed signature
    function authenticate(
        uint256 otp,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry) revert SmsAuthSafe__Expired();
        if (usedNonce[nonce])          revert SmsAuthSafe__Replayed();

        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, msg.sender, otp, nonce, expiry)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != smsService) revert SmsAuthSafe__BadSig();

        usedNonce[nonce] = true;
        emit Authenticated(msg.sender, otp);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) PHONE‑NUMBER WHITELISTING (Smishable Identity)
///─────────────────────────────────────────────────────────────────────────────
error PhoneWL__BadSig();
error PhoneWL__Replayed();

// ❌ Vulnerable: anyone can register any phone → spoofing
contract PhoneWhitelistVuln {
    mapping(string=>bool) public whitelisted;

    function addPhone(string calldata phone) external {
        whitelisted[phone] = true;
    }
}

/// Attack: spoof someone else’s phone
contract Attack_SpoofPhone {
    PhoneWhitelistVuln public target;
    constructor(PhoneWhitelistVuln _t) { target = _t; }

    function exploit(string calldata victimPhone) external {
        target.addPhone(victimPhone);
    }
}

// ✅ Safe: require an off‑chain Phone‑Provider to sign (phone,nonce,expiry)
contract PhoneWhitelistSafe {
    using ECDSALib for bytes32;

    address public immutable phoneProvider;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("PhoneWL(string phone,uint256 nonce,uint256 expiry)");

    mapping(uint256=>bool) public usedNonce;
    mapping(string=>bool) public whitelisted;

    error PhoneWLSafe__Expired();
    error PhoneWLSafe__Replayed();

    event PhoneWhitelisted(string phone);

    constructor(address _phoneProvider) {
        phoneProvider = _phoneProvider;
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("PhoneWLSafe"),
                block.chainid,
                address(this)
            )
        );
    }

    function addPhone(
        string calldata phone,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry) revert PhoneWLSafe__Expired();
        if (usedNonce[nonce])         revert PhoneWLSafe__Replayed();

        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, keccak256(bytes(phone)), nonce, expiry)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != phoneProvider) revert PhoneWL__BadSig();

        usedNonce[nonce] = true;
        whitelisted[phone] = true;
        emit PhoneWhitelisted(phone);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SMS‑LINK EXECUTION (Smishable Callback)
///─────────────────────────────────────────────────────────────────────────────
error LinkExec__BadSig();

// ❌ Vulnerable: executes arbitrary payload from SMS link
contract SmsLinkVuln {
    event Executed(address indexed by, bytes payload);

    function exec(bytes calldata payload) external {
        (bool ok,) = address(this).call(payload);
        require(ok, "SmsLinkVuln: exec failed");
        emit Executed(msg.sender, payload);
    }
}

/// Attack: send victim a malicious link to call selfdestruct etc.
contract Attack_SmsLinkPhish {
    SmsLinkVuln public target;
    constructor(SmsLinkVuln _t) { target = _t; }

    function hack(bytes calldata malicious) external {
        target.exec(malicious);
    }
}

// ✅ Safe: require SMS‑Provider to sign the payload before exec
contract SmsLinkSafe {
    using ECDSALib for bytes32;

    address public immutable smsProvider;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("ExecLink(bytes payload,uint256 nonce,uint256 expiry)");

    mapping(uint256=>bool) public usedNonce;

    error LinkExecSafe__Expired();
    error LinkExecSafe__Replayed();

    event Executed(address indexed by, bytes payload);

    constructor(address _smsProvider) {
        smsProvider = _smsProvider;
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SmsLinkSafe"), 
                block.chainid,
                address(this)
            )
        );
    }

    function exec(
        bytes calldata payload,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry) revert LinkExecSafe__Expired();
        if (usedNonce[nonce])             revert LinkExecSafe__Replayed();

        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, keccak256(payload), nonce, expiry)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != smsProvider) revert LinkExec__BadSig();

        usedNonce[nonce] = true;
        (bool ok,) = address(this).call(payload);
        require(ok, "SmsLinkSafe: exec failed");
        emit Executed(msg.sender, payload);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SMS‑BASED ACCOUNT RECOVERY (Smishable Reset)
///─────────────────────────────────────────────────────────────────────────────
error Recov__BadSig();
error Recov__Expired();
error Recov__Replayed();

// ❌ Vulnerable: nobody-proof reset by phone code alone
contract SmsRecoveryVuln {
    mapping(address=>bytes32) public pwdHash;
    mapping(address=>uint256) public recCode;

    function setRecoveryCode(uint256 code) external {
        recCode[msg.sender] = code;
    }
    function resetPassword(bytes32 newHash, uint256 code) external {
        require(recCode[msg.sender] == code, "SmsRecovVuln: bad code");
        pwdHash[msg.sender] = newHash;
    }
}

/// Attack: phish the code, then call `resetPassword()`
contract Attack_SmsRecoveryPhish {
    SmsRecoveryVuln public target;
    constructor(SmsRecoveryVuln _t) { target = _t; }
    function reset(bytes32 newHash, uint256 code) external {
        target.resetPassword(newHash, code);
    }
}

// ✅ Safe: require user to EIP‑712‑sign the (newHash,nonce,expiry)
contract SmsRecoverySafe {
    using ECDSALib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Recover(address user,bytes32 newHash,uint256 nonce,uint256 expiry)");
    mapping(uint256=>bool) public usedNonce;
    mapping(address=>bytes32) public pwdHash;

    error RecovSafe__Expired();
    error RecovSafe__Replayed();

    event PasswordReset(address indexed user, bytes32 newHash);

    constructor() {
        DOMAIN = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("SmsRecoverySafe"), 
                block.chainid,
                address(this)
            )
        );
    }

    function resetPassword(
        bytes32 newHash,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry) revert RecovSafe__Expired();
        if (usedNonce[nonce])             revert RecovSafe__Replayed();

        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, msg.sender, newHash, nonce, expiry)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != msg.sender) revert Recov__BadSig();

        usedNonce[nonce] = true;
        pwdHash[msg.sender] = newHash;
        emit PasswordReset(msg.sender, newHash);
    }
}
