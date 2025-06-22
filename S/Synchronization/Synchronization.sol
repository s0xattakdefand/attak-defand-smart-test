// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SynchronizationSuite.sol
/// @notice On‑chain analogues of four “synchronization” patterns:
///   1) Mutex (Critical‑Section)  
///   2) Time‑Window Scheduling  
///   3) Cross‑Contract Atomicity  
///   4) Order‑Protection (Front‑Running)  

error Sync__Reentrant();
error TimeSync__TooEarly();
error TimeSync__TooLate();
error Atomic__Failed();
error Auction__NoReveal();
error Auction__BadReveal();

////////////////////////////////////////////////////////////////////////////////
// 1) MUTEX / CRITICAL‑SECTION
//    • Vulnerable: no lock → reentrancy races
//    • Attack: reenter during call to drain extra funds
//    • Defense: nonReentrant mutex
////////////////////////////////////////////////////////////////////////////////
abstract contract NonReentrant {
    uint256 private _status;
    modifier nonReentrant() {
        if (_status == 1) revert Sync__Reentrant();
        _status = 1;
        _;
        _status = 0;
    }
}

contract MutexVuln {
    mapping(address => uint) public balance;
    function deposit() external payable { balance[msg.sender] += msg.value; }
    function withdraw(uint amt) external {
        require(balance[msg.sender] >= amt, "insufficient");
        // ❌ no lock
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        balance[msg.sender] -= amt;
    }
}

contract Attack_Mutex {
    MutexVuln public target;
    constructor(MutexVuln _t) { target = _t; }
    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.withdraw(msg.value);
        }
    }
    function exploit() external payable {
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }
}

contract MutexSafe is NonReentrant {
    mapping(address => uint) public balance;
    function deposit() external payable { balance[msg.sender] += msg.value; }
    function withdraw(uint amt) external nonReentrant {
        require(balance[msg.sender] >= amt, "insufficient");
        balance[msg.sender] -= amt;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) TIME‑WINDOW SCHEDULING
//    • Vulnerable: uses block.timestamp solely → miner can tweak time
//    • Attack: miner shifts timestamp to violate window
//    • Defense: use block.number for hard window bounds
////////////////////////////////////////////////////////////////////////////////
contract TimeWindowVuln {
    uint256 public startTime;
    uint256 public endTime;
    constructor(uint256 _start, uint256 _end) {
        startTime = _start; endTime = _end;
    }
    function enter() external view returns (string memory) {
        require(block.timestamp >= startTime, "too early");
        require(block.timestamp <= endTime,   "too late");
        return "entered";
    }
}

contract TimeWindowSafe {
    uint256 public startBlock;
    uint256 public endBlock;
    constructor(uint256 _blocksFromNow, uint256 _duration) {
        startBlock = block.number + _blocksFromNow;
        endBlock   = startBlock + _duration;
    }
    function enter() external view returns (string memory) {
        require(block.number >= startBlock, "too early");
        require(block.number <= endBlock,   "too late");
        return "entered";
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) CROSS‑CONTRACT ATOMICITY
//    • Vulnerable: partial updates leave inconsistent state
//    • Attack: second call reverts after first succeeded
//    • Defense: wrap both calls and revert on any failure
////////////////////////////////////////////////////////////////////////////////
interface IModule {
    function setVal(uint256 v) external;
}

contract AtomicVuln {
    function multiSet(IModule a, IModule b, uint256 v) external {
        a.setVal(v);
        b.setVal(v); // if this reverts, a is stuck with v
    }
}

contract Attack_Atomic {
    IModule public good;
    IModule public bad;
    constructor(IModule _good, IModule _bad) {
        good = _good; bad = _bad;
    }
    function exploit(uint256 v) external {
        good.setVal(v);
        // simulate revert in bad
        bad.setVal(v * 0); 
    }
}

contract AtomicSafe {
    function multiSet(IModule a, IModule b, uint256 v) external {
        // ✅ ensure atomicity with try/catch
        try a.setVal(v) {} catch {
            revert Atomic__Failed();
        }
        try b.setVal(v) {} catch {
            // rollback a
            revert Atomic__Failed();
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) ORDER‑PROTECTION (FRONT‑RUNNING)
//    • Vulnerable: simple auction can be front‑run
//    • Attack: observe bid in mempool and outbid before mining
//    • Defense: commit‑reveal two‑phase bidding
////////////////////////////////////////////////////////////////////////////////
contract AuctionVuln {
    address public highestBidder;
    uint256 public highestBid;
    function bid() external payable {
        require(msg.value > highestBid, "low bid");
        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }
        highestBidder = msg.sender;
        highestBid    = msg.value;
    }
}

contract AuctionSafe {
    struct Commitment { bytes32 hash; bool revealed; }
    mapping(address => Commitment) public commits;
    uint256 public revealEnd;
    address public winner;
    uint256 public winningBid;

    constructor(uint256 _revealSecs) {
        revealEnd = block.timestamp + _revealSecs;
    }

    // 1) Commit phase
    function commitBid(bytes32 h) external {
        commits[msg.sender] = Commitment({ hash: h, revealed: false });
    }

    // 2) Reveal phase
    function revealBid(uint256 v, bytes32 nonce) external {
        require(block.timestamp <= revealEnd, "reveal over");
        Commitment storage c = commits[msg.sender];
        require(!c.revealed, "already revealed");
        require(keccak256(abi.encodePacked(v, nonce)) == c.hash, "bad reveal");
        c.revealed = true;
        if (v > winningBid) {
            winningBid    = v;
            winner        = msg.sender;
        }
    }

    function finalize() external view returns (address, uint256) {
        require(block.timestamp > revealEnd, "not over");
        return (winner, winningBid);
    }
}
