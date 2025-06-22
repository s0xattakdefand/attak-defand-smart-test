// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DictionaryAttackSuite.sol
/// @notice On‑chain analogues of “Dictionary Attack” patterns:
///   Types: Online, Offline, Hybrid  
///   AttackTypes: CredentialGuess, BulkGuess, PrecomputedHash, ReplayGuess  
///   DefenseTypes: RateLimit, AccountLockout, SlowHash, MultiFactor  

enum DictionaryAttackType    { CredentialGuess, BulkGuess, PrecomputedHash, ReplayGuess }
enum DictionaryDefenseType   { RateLimit, AccountLockout, SlowHash, MultiFactor }
enum DictionaryAttackMode    { Online, Offline, Hybrid }

error DA__TooManyAttempts();
error DA__LockedOut();
error DA__InvalidHash();
error DA__MFARequired();

//////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE AUTHENTICATOR (no limits, no lockout, no slow hash)
//    • Attack: CredentialGuess, BulkGuess (Online)
//////////////////////////////////////////////////////////////////////////////
contract DictAuthVuln {
    mapping(address => bytes32) public passwordHash; // keccak256(password)
    event Login(address indexed who, bool success, DictionaryAttackType attack);

    /// set initial password (insecure, plain keccak)
    function setPassword(bytes32 hash_) external {
        passwordHash[msg.sender] = hash_;
    }

    /// ❌ no rate‑limit or lockout
    function login(bytes32 guess) external {
        bool ok = (passwordHash[msg.sender] == guess);
        emit Login(msg.sender, ok, DictionaryAttackType.CredentialGuess);
    }
}

//////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB (online brute, replay hashed guesses)
//////////////////////////////////////////////////////////////////////////////
contract Attack_DictAuth {
    DictAuthVuln public target;
    constructor(DictAuthVuln _t) { target = _t; }

    /// try a list of guesses
    function bulkGuess(bytes32[] calldata guesses) external {
        for (uint i = 0; i < guesses.length; i++) {
            target.login(guesses[i]);
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// 3) SAFE AUTH WITH RATE‑LIMIT
//    • Defense: RateLimit – cap guesses per block to mitigate bulk attacks
//////////////////////////////////////////////////////////////////////////////
contract DictAuthSafeRate {
    DictAuthVuln public base;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public attemptsInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;
    event Login(address indexed who, bool success, DictionaryDefenseType defense);

    constructor(DictAuthVuln _base) {
        base = _base;
    }

    function login(bytes32 guess) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            attemptsInBlock[msg.sender] = 0;
        }
        attemptsInBlock[msg.sender]++;
        if (attemptsInBlock[msg.sender] > MAX_PER_BLOCK) revert DA__TooManyAttempts();

        bool ok = (base.passwordHash(msg.sender) == guess);
        emit Login(msg.sender, ok, DictionaryDefenseType.RateLimit);
    }
}

//////////////////////////////////////////////////////////////////////////////
// 4) SAFE AUTH WITH ACCOUNT LOCKOUT
//    • Defense: AccountLockout – lock after N failed attempts
//////////////////////////////////////////////////////////////////////////////
contract DictAuthSafeLock {
    mapping(address => bytes32) public passwordHash;
    mapping(address => uint256) public failCount;
    mapping(address => bool)     public locked;
    uint256 public constant MAX_FAIL = 3;
    event Login(address indexed who, bool success, DictionaryDefenseType defense);

    function setPassword(bytes32 hash_) external {
        passwordHash[msg.sender] = hash_;
    }

    function login(bytes32 guess) external {
        if (locked[msg.sender]) revert DA__LockedOut();

        if (passwordHash[msg.sender] == guess) {
            failCount[msg.sender] = 0;
            emit Login(msg.sender, true, DictionaryDefenseType.AccountLockout);
        } else {
            failCount[msg.sender]++;
            if (failCount[msg.sender] >= MAX_FAIL) {
                locked[msg.sender] = true;
            }
            emit Login(msg.sender, false, DictionaryDefenseType.AccountLockout);
        }
    }
}

//////////////////////////////////////////////////////////////////////////////
// 5) SAFE AUTH WITH SLOW HASHING & MULTI‑FACTOR
//    • Defense: SlowHash – enforce cost factor  
//               MultiFactor – require OTP second factor
//////////////////////////////////////////////////////////////////////////////
contract DictAuthSafeStrong {
    mapping(address => bytes32) public passwordHash;    // keccak256(password||salt)
    mapping(address => uint256) public costFactor;      // number of rounds
    mapping(address => bool)    public mfaPassed;
    event Login(address indexed who, bool success, DictionaryDefenseType defense);

    function setCredentials(bytes32 hash_, uint256 rounds) external {
        require(rounds >= 1000, "insufficient slow hash");
        passwordHash[msg.sender] = hash_;
        costFactor[msg.sender] = rounds;
    }

    function passMFA() external {
        mfaPassed[msg.sender] = true;
    }

    function login(bytes32 guess, uint256 rounds) external {
        // enforce cost factor
        require(rounds == costFactor[msg.sender], "bad cost");
        // simulate slow hash by repeating keccak
        bytes32 h = guess;
        for (uint i = 0; i < rounds; i++) {
            h = keccak256(abi.encodePacked(h));
        }
        bool ok = (h == passwordHash[msg.sender]);
        if (!mfaPassed[msg.sender]) revert DA__MFARequired();
        emit Login(msg.sender, ok, DictionaryDefenseType.MultiFactor);
    }
}
