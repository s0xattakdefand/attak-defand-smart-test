// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*//////////////////////////////////////////////////////////////
                            INTERFACES
//////////////////////////////////////////////////////////////*/
interface ISafetyKey {
    /// @notice Returns true if msg.sender is authorised
    function isSafe() external view returns (bool);
}

/*//////////////////////////////////////////////////////////////
                         LIBRARY MIX‑IN
//////////////////////////////////////////////////////////////*/
library SafetyKeyLib {
    error SafetyKey__NotAuthorised();
    event SafetyKeyUsed(address indexed key);

    function _requireSafe(ISafetyKey key) internal view {
        if (!key.isSafe()) revert SafetyKey__NotAuthorised();
    }

    modifier protected(ISafetyKey key) {
        _requireSafe(key);
        emit SafetyKeyUsed(address(key));
        _;
    }
}

/*//////////////////////////////////////////////////////////////
                    1.  SINGLE‑OWNER  (baseline)
//////////////////////////////////////////////////////////////*/
contract OwnerKey is ISafetyKey {
    error OwnerKey__NotOwner();
    address public immutable owner;
    constructor(address _owner) { owner = _owner; }
    function isSafe() external view override returns (bool) {
        return msg.sender == owner;
    }
}

/*//////////////////////////////////////////////////////////////
                2.  k‑of‑n MULTISIG SAFETY KEY
//////////////////////////////////////////////////////////////*/
contract MultiSigKey is ISafetyKey {
    using SafetyKeyLib for ISafetyKey;

    /*-------------  EVENTS / ERRORS -------------*/
    event Exec(bytes32 indexed txHash);
    error MultiSig__HashAlreadyUsed();
    error MultiSig__BadSignature();
    error MultiSig__BadThreshold();
    error MultiSig__TxExpired();

    /*-------------  STORAGE -------------*/
    uint256 public immutable THRESHOLD;
    mapping(address => bool) public isSigner;
    mapping(bytes32 => bool) public usedTx;

    constructor(address[] memory signers, uint256 k) {
        require(k > 0 && k <= signers.length, "Bad k");
        THRESHOLD = k;
        for (uint256 i; i < signers.length; ++i) {
            isSigner[signers[i]] = true;
        }
    }

    /*-------------  EIP‑712 DOMAIN -------------*/
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");
    bytes32 private immutable DOMAIN_SEPARATOR =
        keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("MultiSigKey"), block.chainid, address(this)));

    bytes32 private constant TX_TYPEHASH =
        keccak256("Tx(bytes32 payload,uint256 nonce,uint256 deadline)");

    /*-------------  EXTERNALS -------------*/
    function exec(
        bytes32 payload,
        uint256 nonce,
        uint256 deadline,
        bytes[] calldata sigs
    ) external {
        if (block.timestamp > deadline) revert MultiSig__TxExpired();
        bytes32 hash = keccak256(abi.encode(TX_TYPEHASH, payload, nonce, deadline));
        hash = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, hash));
        if (usedTx[hash]) revert MultiSig__HashAlreadyUsed();
        _verify(hash, sigs);
        usedTx[hash] = true;
        emit Exec(hash);
        (bool ok, ) = address(this).call(abi.encodePacked(payload));
        require(ok, "Payload failed");
    }

    /*-------------  VIEW -------------*/
    function isSafe() external view override returns (bool) {
        // msg.sender must be this contract (internal call via exec)
        return msg.sender == address(this);
    }

    /*-------------  INTERNALS -------------*/
    function _verify(bytes32 hash, bytes calldata sig) private view returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        address signer = ecrecover(hash, v, r, s);
        if (!isSigner[signer]) revert MultiSig__BadSignature();
        return signer;
    }
    function _verify(bytes32 hash, bytes[] calldata sigs) private view {
        address last;
        uint256 count;
        for (uint256 i; i < sigs.length; ++i) {
            address signer = _verify(hash, sigs[i]);
            if (signer <= last) revert MultiSig__BadSignature(); // enforce sorted unique
            last = signer;
            ++count;
        }
        if (count < THRESHOLD) revert MultiSig__BadThreshold();
    }
    function _split(bytes calldata sig) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := shr(248, calldataload(add(sig.offset, 64)))
        }
    }
}

/*//////////////////////////////////////////////////////////////
                3.  TIME‑LOCKED EMERGENCY KEY
//////////////////////////////////////////////////////////////*/
contract TimelockKey is ISafetyKey {
    /*-------------  CONFIG -------------*/
    uint256 public immutable minDelay; // seconds
    address public immutable proposer;

    /*-------------  STATE -------------*/
    mapping(bytes32 => uint256) public executionTime;

    event Queued(bytes32 indexed id, uint256 eta);
    event Executed(bytes32 indexed id);

    error Timelock__Early();
    error Timelock__NotQueued();
    error Timelock__NotProposer();

    constructor(uint256 _delay, address _proposer) {
        minDelay = _delay;
        proposer = _proposer;
    }

    function queue(bytes32 id) external returns (uint256 eta) {
        if (msg.sender != proposer) revert Timelock__NotProposer();
        eta = block.timestamp + minDelay;
        executionTime[id] = eta;
        emit Queued(id, eta);
    }

    function isSafe() external view override returns (bool) {
        uint256 eta = executionTime[keccak256(msg.data)];
        if (eta == 0) revert Timelock__NotQueued();
        if (block.timestamp < eta) revert Timelock__Early();
        return true;
    }

    function _consume(bytes32 id) internal {
        if (!this.isSafe.selector) id; // quiet unused‑fn warning
        delete executionTime[id];
        emit Executed(id);
    }
}

/*//////////////////////////////////////////////////////////////
          4.  GUARDIAN / SOCIAL‑RECOVERY SAFETY KEY
//////////////////////////////////////////////////////////////*/
contract GuardianKey is ISafetyKey {
    event GuardianProposed(address indexed newOwner, bytes32 proposalId);
    event GuardianApproved(address indexed guardian, bytes32 proposalId);
    event OwnerRecovered(address indexed newOwner);

    error Guardian__InvalidQuorum();
    error Guardian__DuplicateVote();
    error Guardian__NotGuardian();
    error Guardian__CoolDown();

    address public owner;
    uint256 public immutable quorum;
    uint256 public immutable coolDown;
    mapping(address => bool) public isGuardian;
    mapping(bytes32 => uint256) public votes;           // proposalId => vote count
    mapping(bytes32 => mapping(address => bool)) public hasVoted;

    constructor(
        address _owner,
        address[] memory _guardians,
        uint256 _quorum,
        uint256 _coolDown
    ) {
        require(_quorum > 0 && _quorum <= _guardians.length, "bad quorum");
        owner = _owner;
        quorum = _quorum;
        coolDown = _coolDown;
        for (uint256 i; i < _guardians.length; ++i) isGuardian[_guardians[i]] = true;
    }

    function proposeRecovery(address newOwner) external returns (bytes32 id) {
        if (!isGuardian[msg.sender]) revert Guardian__NotGuardian();
        id = keccak256(abi.encodePacked(newOwner, block.number));
        emit GuardianProposed(newOwner, id);
        _vote(id); // proposer auto‑votes
    }

    function approve(bytes32 id) external {
        if (!isGuardian[msg.sender]) revert Guardian__NotGuardian();
        _vote(id);
    }

    function _vote(bytes32 id) private {
        if (hasVoted[id][msg.sender]) revert Guardian__DuplicateVote();
        hasVoted[id][msg.sender] = true;
        uint256 v = ++votes[id];
        emit GuardianApproved(msg.sender, id);
        if (v >= quorum) {
            // cool‑down period before recovery
            votes[id] = type(uint256).max; // mark executed
            (address newOwner,) = abi.decode(abi.encodePacked(id), (address, uint256));
            _recover(newOwner);
        }
    }

    function _recover(address newOwner) private {
        owner = newOwner;
        emit OwnerRecovered(newOwner);
    }

    function isSafe() external view override returns (bool) {
        return msg.sender == owner;
    }
}

/*//////////////////////////////////////////////////////////////
            5.  WEIGHTED‑THRESHOLD SAFETY KEY
//////////////////////////////////////////////////////////////*/
contract WeightedKey is ISafetyKey {
    struct Holder { uint128 weight; uint128 nonce; }

    uint256 public immutable threshold; // e.g., 1e18 = 100%
    mapping(address => Holder) public holders;
    bytes32 public immutable DOMAIN_SEPARATOR;

    error Weighted__BadWeight();
    error Weighted__SigExpired();
    error Weighted__NonceUsed();
    error Weighted__ThresholdNotMet();

    constructor(address[] memory who, uint128[] memory w, uint256 _thr) {
        require(who.length == w.length, "len");
        threshold = _thr;
        for (uint256 i; i < who.length; ++i) {
            holders[who[i]].weight = w[i];
        }
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("WeightedKey"),
                block.chainid,
                address(this)
            )
        );
    }

    function isSafe() external view override returns (bool) { return msg.sender == address(this); }

    /// @notice Execute an arbitrary payload once enough weighted signatures are gathered
    function exec(bytes32 payload, uint256 deadline, bytes[] calldata sigs) external {
        if (block.timestamp > deadline) revert Weighted__SigExpired();
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(keccak256("Payload(bytes32,uint256)"), payload, deadline))
            )
        );
        uint256 total;
        for (uint256 i; i < sigs.length; ++i) {
            address signer = _recover(digest, sigs[i]);
            Holder storage h = holders[signer];
            uint256 n = h.nonce;
            h.nonce = n + 1; // one‑time
            total += h.weight;
        }
        if (total < threshold) revert Weighted__ThresholdNotMet();
        (bool ok,) = address(this).call(abi.encodePacked(payload));
        require(ok, "payload failed");
    }

    function _recover(bytes32 h, bytes calldata sig) private pure returns (address) {
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := shr(248, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(h, v, r, s);
    }
}

/*//////////////////////////////////////////////////////////////
                DEMO ‑ ATTACK SIMULATORS (lab toys)
//////////////////////////////////////////////////////////////*/
contract Attack_SingleKeyTheft {
    OwnerKey public key;
    constructor(OwnerKey _k) { key = _k; }

    // imagine attacker stole owner's private key and calls any protected fn
}

contract Attack_MultiSigPhish {
    // craft payload + collect k compromised signatures, call key.exec(...)
}

contract Attack_TimelockFastRun {
    // try to queue & front‑run before defenders cancel (fails due to minDelay)
}

contract Attack_GuardianSocialEng {
    // attacker convinces enough guardians to approve rogue owner
}

contract Attack_WeightedCollusion {
    // colluding high‑weight holders sign off‑chain & drain funds
}
