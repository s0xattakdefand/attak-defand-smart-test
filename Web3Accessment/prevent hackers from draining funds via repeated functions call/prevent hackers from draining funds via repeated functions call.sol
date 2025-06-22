// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title FundDrainPreventionSuite.sol
/// @notice “Prevent hackers from draining funds via repeated function call” patterns:
///   Types: Vulnerable, ChecksEffectsInteractions, MutexGuard, RateLimitGuard, PullPayment  
///   AttackTypes: Reentrancy, FloodCall, Draining  
///   DefenseTypes: CEI, MutexGuard, RateLimit, PullPayment, CircuitBreaker

enum FDPType             { Vulnerable, ChecksEffectsInteractions, MutexGuard, RateLimitGuard, PullPayment }
enum FDPAttackType       { Reentrancy, FloodCall, Draining }
enum FDPDefenseType      { CEI, MutexGuard, RateLimit, PullPayment, CircuitBreaker }

error FDP__Reentrant();
error FDP__TooManyRequests();
error FDP__InsufficientBalance();
error FDP__CircuitOpen();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WALLET
//    • ❌ no protection: external call before state update → Reentrancy
////////////////////////////////////////////////////////////////////////////////
contract FundDrainVuln {
    mapping(address => uint256) public balances;
    event Withdrawal(address indexed who, uint256 amount, FDPType dtype, FDPAttackType attack);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // vulnerable: call before state change
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount, FDPType.Vulnerable, FDPAttackType.Reentrancy);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates reentrancy & flood calls to drain funds
////////////////////////////////////////////////////////////////////////////////
contract Attack_FundDrain {
    FundDrainVuln public target;
    constructor(FundDrainVuln _t) { target = _t; }

    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw(msg.value);
        }
    }

    function attack() external payable {
        // seed
        target.deposit{value: msg.value}();
        // trigger reentrancy
        target.withdraw(msg.value);
    }

    function floodWithdraw(uint256 amount, uint256 times) external {
        for (uint i; i < times; ++i) {
            target.withdraw(amount);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH CHECKS‐EFFECTS‐INTERACTIONS
//    • ✅ Defense: CEI – update state before external call
////////////////////////////////////////////////////////////////////////////////
contract FundDrainSafeCEI {
    mapping(address => uint256) public balances;
    event Withdrawal(address indexed who, uint256 amount, FDPType dtype, FDPDefenseType defense);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        if (balances[msg.sender] < amount) revert FDP__InsufficientBalance();
        // effects
        balances[msg.sender] -= amount;
        // interaction
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        emit Withdrawal(msg.sender, amount, FDPType.ChecksEffectsInteractions, FDPDefenseType.CEI);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH MUTEX GUARD & RATE LIMIT
//    • ✅ Defense: MutexGuard – single‐entry  
//               RateLimit   – cap withdraws per block
////////////////////////////////////////////////////////////////////////////////
contract FundDrainSafeMutexRate {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    bool private _entered;
    uint256 public constant MAX_CALLS = 3;

    event Withdrawal(address indexed who, uint256 amount, FDPType dtype, FDPDefenseType defense);

    modifier noReentry() {
        if (_entered) revert FDP__Reentrant();
        _entered = true;
        _;
        _entered = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external noReentry {
        if (balances[msg.sender] < amount) revert FDP__InsufficientBalance();
        // rate‐limit per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert FDP__TooManyRequests();

        balances[msg.sender] -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        emit Withdrawal(msg.sender, amount, FDPType.MutexGuard, FDPDefenseType.MutexGuard);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH PULL PAYMENT & CIRCUIT BREAKER
//    • ✅ Defense: PullPayment  – beneficiary pulls funds  
//               CircuitBreaker – stop withdrawals on emergency
////////////////////////////////////////////////////////////////////////////////
contract FundDrainSafePull {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public pending;
    bool public halted;
    event Deposit(address indexed who, uint256 amount, FDPType dtype, FDPDefenseType defense);
    event Withdrawn(address indexed who, uint256 amount, FDPType dtype, FDPDefenseType defense);
    event EmergencyTriggered(address indexed by);

    modifier notHalted() {
        if (halted) revert FDP__CircuitOpen();
        _;
    }

    /// @notice owner can halt withdrawals in an emergency
    address public owner;
    constructor() { owner = msg.sender; }

    function triggerEmergency() external {
        require(msg.sender == owner, "only owner");
        halted = true;
        emit EmergencyTriggered(msg.sender);
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        pending[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value, FDPType.PullPayment, FDPDefenseType.PullPayment);
    }

    function withdraw() external notHalted {
        uint256 amount = pending[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pending[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        emit Withdrawn(msg.sender, amount, FDPType.PullPayment, FDPDefenseType.PullPayment);
    }
}
