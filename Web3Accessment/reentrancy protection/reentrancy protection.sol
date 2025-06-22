// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ReentrancyProtectionSuite.sol
/// @notice On‐chain analogues of “Reentrancy Protection” patterns:
///   Types: BasicGuard, PullPaymentPattern, ChecksEffectsInteractions, RateLimit, SignatureValidation  
///   AttackTypes: BasicReentrancy, NestedReentrancy, CrossFunctionReentrancy, GasLimitBypass  
///   DefenseTypes: MutexGuard, PullPayment, CEI, RateLimit, SignatureValidation

enum RPType                { BasicGuard, PullPaymentPattern, ChecksEffectsInteractions, RateLimit, SignatureValidation }
enum RPAttackType          { BasicReentrancy, NestedReentrancy, CrossFunctionReentrancy, GasLimitBypass }
enum RPDefenseType         { MutexGuard, PullPayment, CEI, RateLimit, SignatureValidation }

error RP__Reentrant();
error RP__TooManyRequests();
error RP__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WALLET
//    • ❌ no guard: reentrancy → BasicReentrancy
////////////////////////////////////////////////////////////////////////////////
contract RPVuln {
    mapping(address => uint256) public balances;
    event Withdrawal(address indexed who, uint256 amount, RPType dtype, RPAttackType attack);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // vulnerable external call before state update
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount, RPType.BasicGuard, RPAttackType.BasicReentrancy);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates basic and nested reentrancy
////////////////////////////////////////////////////////////////////////////////
contract Attack_Reentrancy {
    RPVuln public target;
    constructor(RPVuln _t) { target = _t; }

    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw(msg.value);
        }
    }

    function attack(uint256 depositAmt) external payable {
        require(msg.value == depositAmt, "send depositAmt");
        target.deposit{value: msg.value}();
        target.withdraw(depositAmt);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH MUTEX GUARD
//    • ✅ Defense: MutexGuard – single‐entry withdraw
////////////////////////////////////////////////////////////////////////////////
contract RPSafeMutex {
    mapping(address => uint256) public balances;
    bool private _entered;
    event Withdrawal(address indexed who, uint256 amount, RPType dtype, RPDefenseType defense);

    modifier noReentry() {
        if (_entered) revert RP__Reentrant();
        _entered = true;
        _;
        _entered = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external noReentry {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        emit Withdrawal(msg.sender, amount, RPType.BasicGuard, RPDefenseType.MutexGuard);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH PULL PAYMENT & RATE LIMIT
//    • ✅ Defense: PullPayment – beneficiary pulls  
//               RateLimit    – cap withdrawals per block
////////////////////////////////////////////////////////////////////////////////
contract RPSafePull {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public pending;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 3;
    event Deposit(address indexed who, uint256 amount, RPType dtype, RPDefenseType defense);
    event Withdrawn(address indexed who, uint256 amount, RPType dtype, RPDefenseType defense);

    error RP__TooManyRequests();

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        pending[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value, RPType.PullPaymentPattern, RPDefenseType.PullPayment);
    }

    function withdraw() external {
        // rate‐limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert RP__TooManyRequests();

        uint256 amount = pending[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pending[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        emit Withdrawn(msg.sender, amount, RPType.PullPaymentPattern, RPDefenseType.PullPayment);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH CEI & SIGNATURE VALIDATION
//    • ✅ Defense: ChecksEffectsInteractions – update before call  
//               SignatureValidation            – admin‐signed large withdraws
////////////////////////////////////////////////////////////////////////////////
contract RPSafeAdvanced {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastExec;
    address public signer;
    event Withdrawal(address indexed who, uint256 amount, RPType dtype, RPDefenseType defense);

    error RP__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(
        uint256 amount,
        bytes calldata sig
    ) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // signature required for large amounts
        if (amount > 1 ether) {
            bytes32 h = keccak256(abi.encodePacked(msg.sender, amount));
            bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
            (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
            if (ecrecover(eth, v, r, s) != signer) revert RP__InvalidSignature();
        }
        // CEI: effects first
        balances[msg.sender] -= amount;
        lastExec[msg.sender] = block.timestamp;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        emit Withdrawal(msg.sender, amount, RPType.ChecksEffectsInteractions, RPDefenseType.CEI);
    }
}
