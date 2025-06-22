// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

///─────────────────────────────────────────────────────────────────────────────
///                             ECDSA HELPER LIBRARY
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
/// 1) PIN‑PROTECTED ACCESS
///─────────────────────────────────────────────────────────────────────────────
// Vulnerable: stores PIN in plaintext; attacker can brute‑force via view()
contract PinCardVuln {
    mapping(address => uint256) public pin;
    function setPin(uint256 _pin) external { pin[msg.sender] = _pin; }
    function access(uint256 _pin) external view returns (bool) {
        return pin[msg.sender] == _pin;
    }
}

/// Attack: simply call `access()` with guesses
contract Attack_PinBrute {
    PinCardVuln public card;
    constructor(PinCardVuln _c) { card = _c; }
    function brute(uint256 guess) external view returns (bool) {
        return card.access(guess);
    }
}

// Safe: store only keccak256‑hashed PIN
contract PinCardSafe {
    mapping(address => bytes32) private pinHash;
    event PinSet(address indexed who);

    function setPin(uint256 _pin) external {
        pinHash[msg.sender] = keccak256(abi.encodePacked(_pin));
        emit PinSet(msg.sender);
    }

    function access(uint256 _pin) external view returns (bool) {
        return pinHash[msg.sender] == keccak256(abi.encodePacked(_pin));
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) OTP‑BASED AUTHORIZATION
///─────────────────────────────────────────────────────────────────────────────
// Vulnerable: static OTP signed by manager, no nonce/expiry → replayable
contract OTPCardVuln {
    using ECDSALib for bytes32;
    address public immutable manager;

    constructor(address _mgr) { manager = _mgr; }

    /// @notice Verify manager’s eth_sign(msg.sender‖otp)
    function verifyOTP(bytes calldata sig, uint256 otp) external view returns (bool) {
        bytes32 h = keccak256(abi.encodePacked(msg.sender, otp)).toEthSignedMessageHash();
        return h.recover(sig) == manager;
    }
}

/// Attack: reuse the same signed OTP indefinitely
contract Attack_OTPReplay {
    OTPCardVuln public card;
    bytes         public sig;
    uint256       public otp;

    constructor(OTPCardVuln _c, bytes memory _sig, uint256 _otp) {
        card = _c;
        sig  = _sig;
        otp  = _otp;
    }

    function replay() external view returns (bool) {
        // succeeds every time, no replay protection
        return card.verifyOTP(sig, otp);
    }
}

// Safe: bind each OTP to nonce + expiry via EIP‑712
contract OTPCardSafe {
    using ECDSALib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("OTP(address who,uint256 otp,uint256 nonce,uint256 expiry)");

    address public immutable manager;
    mapping(uint256 => bool) public usedNonce;

    error OTP__BadSig();
    error OTP__Expired();
    error OTP__Replayed();

    constructor(address _mgr) {
        manager = _mgr;
        DOMAIN  = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("OTPCardSafe"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Validate signed OTP and mark nonce used
    function verifyOTP(
        uint256 otp,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry)        revert OTP__Expired();
        if (usedNonce[nonce])                revert OTP__Replayed();

        bytes32 structHash = keccak256(
            abi.encode(TYPEHASH, msg.sender, otp, nonce, expiry)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer = digest.recover(sig);
        if (signer != manager) revert OTP__BadSig();

        usedNonce[nonce] = true;
        // OTP accepted
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) CARD LOCKOUT ON FAILED PIN
///─────────────────────────────────────────────────────────────────────────────
// Vulnerable: unlimited PIN attempts, no lockout
contract LockableCardVuln {
    mapping(address => bytes32) public pinHash;
    function setPin(string calldata pin) external {
        pinHash[msg.sender] = keccak256(abi.encodePacked(pin));
    }
    function access(string calldata pin) external view returns (bool) {
        return pinHash[msg.sender] == keccak256(abi.encodePacked(pin));
    }
}

/// Attack: brute‑force without ever being locked
contract Attack_CardLockout {
    LockableCardVuln public card;
    constructor(LockableCardVuln _c) { card = _c; }
    function brute(string calldata guess) external view returns (bool) {
        return card.access(guess);
    }
}

// Safe: lock the card after 3 wrong PIN attempts
contract LockableCardSafe {
    mapping(address => bytes32) private pinHash;
    mapping(address => uint8)  private attempts;
    mapping(address => bool)   private locked;

    uint8  public constant MAX_ATTEMPTS = 3;
    error Card__Locked();
    error Card__BadPin();

    event Locked(address indexed who);
    event Unlocked(address indexed who);

    function setPin(string calldata pin) external {
        pinHash[msg.sender] = keccak256(abi.encodePacked(pin));
        attempts[msg.sender] = 0;
        locked[msg.sender]   = false;
    }

    function access(string calldata pin) external {
        if (locked[msg.sender]) revert Card__Locked();
        if (pinHash[msg.sender] != keccak256(abi.encodePacked(pin))) {
            attempts[msg.sender] ++;
            if (attempts[msg.sender] >= MAX_ATTEMPTS) {
                locked[msg.sender] = true;
                emit Locked(msg.sender);
            }
            revert Card__BadPin();
        }
        // correct PIN → reset counter
        attempts[msg.sender] = 0;
    }

    function isLocked() external view returns (bool) {
        return locked[msg.sender];
    }

    function unlock() external {
        // user may reset by calling setPin(); or allow admin unlock if desired
        attempts[msg.sender] = 0;
        locked[msg.sender]   = false;
        emit Unlocked(msg.sender);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SPENDING‑LIMIT WALLET
///─────────────────────────────────────────────────────────────────────────────
// Vulnerable: no limit on withdrawals → attacker drains for large amount
contract LimitCardVuln {
    mapping(address => uint256) public balance;
    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }
    function withdraw(uint256 amt) external {
        require(balance[msg.sender] >= amt, "Insufficient");
        balance[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Transfer failed");
    }
}

/// Attack: keep calling withdraw() up to entire balance
contract Attack_LimitBypass {
    LimitCardVuln public card;
    constructor(LimitCardVuln _c) { card = _c; }
    function drain() external {
        uint256 bal = address(card).balance;
        card.withdraw(bal);
    }
}

// Safe: enforce a per‑day spending cap
contract LimitCardSafe {
    mapping(address => uint256) public balance;
    mapping(address => uint256) public spentToday;
    mapping(address => uint256) public lastDay;

    uint256 public constant DAILY_LIMIT = 1 ether;
    error Limit__Exceeded();
    error Balance__Insufficient();

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    function withdraw(uint256 amt) external {
        uint256 day = block.timestamp / 1 days;
        if (lastDay[msg.sender] != day) {
            spentToday[msg.sender] = 0;
            lastDay[msg.sender]    = day;
        }
        if (spentToday[msg.sender] + amt > DAILY_LIMIT) revert Limit__Exceeded();
        if (balance[msg.sender] < amt)                revert Balance__Insufficient();

        spentToday[msg.sender] += amt;
        balance[msg.sender]   -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "Transfer failed");
    }

    function availableToday() external view returns (uint256) {
        uint256 day = block.timestamp / 1 days;
        if (lastDay[msg.sender] != day) return DAILY_LIMIT;
        return DAILY_LIMIT - spentToday[msg.sender];
    }
}
