// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CallBackSuite.sol
/// @notice On‐chain analogues of “Callback” invocation patterns:
///   Types: HTTP, Webhook, OnChainEvent, DelegateCall  
///   AttackTypes: Reentrancy, UnauthorizedInvoke, PayloadTampering, DoS  
///   DefenseTypes: AccessControl, NonReentrant, InputValidation, RateLimit, SignatureValidation

enum CallBackType           { HTTP, Webhook, OnChainEvent, DelegateCall }
enum CallBackAttackType     { Reentrancy, UnauthorizedInvoke, PayloadTampering, DoS }
enum CallBackDefenseType    { AccessControl, NonReentrant, InputValidation, RateLimit, SignatureValidation }

error CB__NotOwner();
error CB__Reentrant();
error CB__InvalidInput();
error CB__TooManyRequests();
error CB__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CALLBACK MANAGER
//    • ❌ no checks: anyone may register/trigger → UnauthorizedInvoke, Reentrancy
////////////////////////////////////////////////////////////////////////////////
contract CallBackVuln {
    mapping(CallBackType => address) public callbacks;

    event CallbackTriggered(
        address indexed who,
        CallBackType      cbType,
        CallBackAttackType attack
    );

    function registerCallback(CallBackType cbType, address target) external {
        callbacks[cbType] = target;
    }

    function trigger(CallBackType cbType, bytes calldata data) external {
        address cb = callbacks[cbType];
        // naive external call without checks
        (bool ok,) = cb.call(data);
        require(ok, "callback failed");
        emit CallbackTriggered(msg.sender, cbType, CallBackAttackType.Reentrancy);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates reentrancy, unauthorized invocation, DoS
////////////////////////////////////////////////////////////////////////////////
contract Attack_CallBack {
    CallBackVuln public target;
    bool public inAttack;

    constructor(CallBackVuln _t) { target = _t; }

    // malicious callback that re-enters trigger
    fallback() external {
        if (!inAttack) {
            inAttack = true;
            target.trigger(CallBackType.OnChainEvent, "");
        }
    }

    function setupAndExploit(address registry) external {
        // register this contract as callback
        target.registerCallback(CallBackType.OnChainEvent, address(this));
        // trigger to invoke fallback reentrancy
        target.trigger(CallBackType.OnChainEvent, "");
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may register/trigger
////////////////////////////////////////////////////////////////////////////////
contract CallBackSafeAccess {
    mapping(CallBackType => address) public callbacks;
    address public owner;

    event CallbackTriggered(
        address indexed who,
        CallBackType      cbType,
        CallBackDefenseType defense
    );
    error CB__NotOwner();

    constructor() { owner = msg.sender; }

    function registerCallback(CallBackType cbType, address target_) external {
        if (msg.sender != owner) revert CB__NotOwner();
        callbacks[cbType] = target_;
    }

    function trigger(CallBackType cbType, bytes calldata data) external {
        if (msg.sender != owner) revert CB__NotOwner();
        address cb = callbacks[cbType];
        (bool ok,) = cb.call(data);
        require(ok, "callback failed");
        emit CallbackTriggered(msg.sender, cbType, CallBackDefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH NON‐REENTRANT GUARD & INPUT VALIDATION
//    • ✅ Defense: NonReentrant – guard reentrancy  
//               InputValidation – nonzero target address
////////////////////////////////////////////////////////////////////////////////
contract CallBackSafeNonReentrant {
    mapping(CallBackType => address) public callbacks;
    bool private locked;

    event CallbackTriggered(
        address indexed who,
        CallBackType      cbType,
        CallBackDefenseType defense
    );
    error CB__Reentrant();
    error CB__InvalidInput();

    modifier nonReentrant() {
        if (locked) revert CB__Reentrant();
        locked = true;
        _;
        locked = false;
    }

    function registerCallback(CallBackType cbType, address target_) external {
        if (target_ == address(0)) revert CB__InvalidInput();
        callbacks[cbType] = target_;
    }

    function trigger(CallBackType cbType, bytes calldata data) external nonReentrant {
        address cb = callbacks[cbType];
        if (cb == address(0)) revert CB__InvalidInput();
        (bool ok,) = cb.call(data);
        require(ok, "callback failed");
        emit CallbackTriggered(msg.sender, cbType, CallBackDefenseType.NonReentrant);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & RATE LIMIT
//    • ✅ Defense: SignatureValidation – require signed cbType+target  
//               RateLimit – cap triggers per block
////////////////////////////////////////////////////////////////////////////////
contract CallBackSafeAdvanced {
    mapping(CallBackType => address) public callbacks;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    address public signer;
    uint256 public constant MAX_CALLS = 3;

    event CallbackTriggered(
        address indexed who,
        CallBackType      cbType,
        CallBackDefenseType defense
    );
    error CB__TooManyRequests();
    error CB__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function registerCallback(
        CallBackType cbType,
        address target_,
        bytes calldata sig
    ) external {
        // verify signature over (uint8(cbType)||target_)
        bytes32 h = keccak256(abi.encodePacked(uint8(cbType), target_));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert CB__InvalidSignature();
        callbacks[cbType] = target_;
    }

    function trigger(CallBackType cbType, bytes calldata data) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert CB__TooManyRequests();

        address cb = callbacks[cbType];
        (bool ok,) = cb.call(data);
        require(ok, "callback failed");
        emit CallbackTriggered(msg.sender, cbType, CallBackDefenseType.RateLimit);
    }
}
