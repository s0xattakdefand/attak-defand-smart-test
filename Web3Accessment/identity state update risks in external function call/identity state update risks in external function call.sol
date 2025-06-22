// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IdentityStateUpdateRisksSuite.sol
/// @notice On‐chain analogues of “Identity State Update Risks in External Function Calls” patterns:
///   Types: DirectUpdate, DelegateCallUpdate, CrossContractUpdate, BatchUpdate  
///   AttackTypes: StateHijack, Replay, DelegateCallHijack, UnauthorizedBatch  
///   DefenseTypes: CEI, AccessControl, SignatureValidation, RateLimit, DelegateGuard

enum IdentityStateType     { DirectUpdate, DelegateCallUpdate, CrossContractUpdate, BatchUpdate }
enum ISAttackType          { StateHijack, Replay, DelegateCallHijack, UnauthorizedBatch }
enum ISDefenseType         { CEI, AccessControl, SignatureValidation, RateLimit, DelegateGuard }

error IS__Reentrant();
error IS__NotAuthorized();
error IS__TooManyRequests();
error IS__InvalidSignature();
error IS__DelegateCallBlocked();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE IDENTITY MANAGER
//    • ❌ no guard: external call before updating state → StateHijack, Replay
////////////////////////////////////////////////////////////////////////////////
contract ISVuln {
    mapping(address => uint256) public nonces;
    mapping(address => bytes32) public identityHash;

    event IdentityUpdated(
        address indexed who,
        bytes32           newHash,
        IdentityStateType itype,
        ISAttackType      attack
    );

    function updateIdentity(bytes32 newHash) external {
        // vulnerable: external call triggers before state change
        (bool ok,) = msg.sender.call{gas: 50000}("");
        require(ok);
        // replayable: nonce not incremented prior to call
        identityHash[msg.sender] = newHash;
        emit IdentityUpdated(msg.sender, newHash, IdentityStateType.DirectUpdate, ISAttackType.StateHijack);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates hijack via reentry, replay, delegatecall hijack
////////////////////////////////////////////////////////////////////////////////
contract Attack_IS {
    ISVuln public target;
    bytes32 public lastHash;

    constructor(ISVuln _t) {
        target = _t;
    }

    receive() external payable {
        // reenter to hijack state
        target.updateIdentity(keccak256("hacked"));
    }

    function hijack() external {
        // trigger reentrancy
        target.updateIdentity(keccak256("attack"));
        lastHash = keccak256("attack");
    }

    function replay() external {
        // replay old call
        target.updateIdentity(lastHash);
    }

    function delegateHack(address impl, bytes32 h) external {
        // hijack via delegatecall path
        (bool ok,) = address(target).delegatecall(
            abi.encodeWithSelector(ISVuln.updateIdentity.selector, h)
        );
        require(ok);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH CHECKS‐EFFECTS‐INTERACTIONS
//    • ✅ Defense: CEI – update state before any external interaction
////////////////////////////////////////////////////////////////////////////////
contract ISSafeCEI {
    mapping(address => uint256) public nonces;
    mapping(address => bytes32) public identityHash;

    event IdentityUpdated(
        address indexed who,
        bytes32           newHash,
        IdentityStateType itype,
        ISDefenseType     defense
    );

    function updateIdentity(bytes32 newHash) external {
        // effects
        nonces[msg.sender]++;
        identityHash[msg.sender] = newHash;
        // interactions
        (bool ok,) = msg.sender.call{gas: 50000}("");
        require(ok);
        emit IdentityUpdated(msg.sender, newHash, IdentityStateType.DirectUpdate, ISDefenseType.CEI);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH ACCESS CONTROL & RATE LIMIT
//    • ✅ Defense: AccessControl – only whitelisted may update  
//               RateLimit      – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract ISSafeAccessRate {
    mapping(address => bytes32) public identityHash;
    mapping(address => bool)    public authorized;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;

    event IdentityUpdated(
        address indexed who,
        bytes32           newHash,
        IdentityStateType itype,
        ISDefenseType     defense
    );

    error IS__NotAuthorized();
    error IS__TooManyRequests();

    modifier onlyAuth() {
        if (!authorized[msg.sender]) revert IS__NotAuthorized();
        _;
    }

    constructor() {
        authorized[msg.sender] = true;
    }

    function setAuthorized(address user, bool ok) external {
        authorized[msg.sender] = true; // simplistic admin stub
        authorized[user] = ok;
    }

    function updateIdentity(bytes32 newHash) external onlyAuth {
        // rate‐limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert IS__TooManyRequests();

        identityHash[msg.sender] = newHash;
        (bool ok,) = msg.sender.call{gas: 50000}("");
        require(ok);
        emit IdentityUpdated(msg.sender, newHash, IdentityStateType.DirectUpdate, ISDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & DELEGATE GUARD
//    • ✅ Defense: SignatureValidation – require off‐chain signed newHash  
//               DelegateGuard         – block delegatecalls to updateIdentity
////////////////////////////////////////////////////////////////////////////////
contract ISSafeAdvanced {
    mapping(address => bytes32) public identityHash;
    address public signer;
    event IdentityUpdated(
        address indexed who,
        bytes32           newHash,
        IdentityStateType itype,
        ISDefenseType     defense
    );
    error IS__InvalidSignature();
    error IS__DelegateCallBlocked();

    constructor(address _signer) {
        signer = _signer;
    }

    modifier noDelegate() {
        // prevent delegatecall hijack
        if (address(this) != msg.sender) revert IS__DelegateCallBlocked();
        _;
    }

    function updateIdentity(bytes32 newHash, bytes calldata sig)
        external
        noDelegate
    {
        // verify signature over (msg.sender||newHash)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, newHash));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert IS__InvalidSignature();

        identityHash[msg.sender] = newHash;
        emit IdentityUpdated(msg.sender, newHash, IdentityStateType.DirectUpdate, ISDefenseType.SignatureValidation);
    }
}
