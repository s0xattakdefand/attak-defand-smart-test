// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SniffingSuite.sol
/// @notice On‑chain analogues of four common “sniffing” patterns:
///   1) Storage Sniffing  
///   2) Event Sniffing  
///   3) Mempool Sniffing (Commit–Reveal)  
///   4) Oracle Sniffing  

error Sniff__AlreadyRevealed();
error Sniff__BadHash();
error Sniff__NotAuthorized();

////////////////////////////////////////////////////////////////////////////////
// 1) STORAGE SNIFFING
//
//   * Vulnerable: public storage leaks private data
//   * Attack: read another user’s secret via public getter
//   * Defense: keep storage private and only expose verify()
// 
////////////////////////////////////////////////////////////////////////////////
contract StorageSniffVuln {
    mapping(address => uint256) public secret;
    function setSecret(uint256 s) external {
        secret[msg.sender] = s;
    }
}

contract Attack_StorageSniff {
    StorageSniffVuln public target;
    constructor(StorageSniffVuln _t) { target = _t; }
    function sniff(address user) external view returns (uint256) {
        return target.secret(user);
    }
}

contract StorageSniffSafe {
    mapping(address => uint256) private _secret;
    event SecretSet(address indexed who);
    function setSecret(uint256 s) external {
        _secret[msg.sender] = s;
        emit SecretSet(msg.sender);
    }
    function verifySecret(uint256 s) external view returns (bool) {
        return _secret[msg.sender] == s;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) EVENT SNIFFING
//
//   * Vulnerable: emitting plaintext in events leaks off‑chain
//   * Attack: listen to logs for secrets
//   * Defense: emit only hash of sensitive data
// 
////////////////////////////////////////////////////////////////////////////////
contract EventSniffVuln {
    event Leak(address indexed who, uint256 secret);
    function store(uint256 s) external {
        emit Leak(msg.sender, s);
    }
}

contract Attack_EventSniff {
    EventSniffVuln public target;
    constructor(EventSniffVuln _t) { target = _t; }
    function storeAndLeak(uint256 s) external {
        target.store(s);
        // off‑chain observer sees `Leak(msg.sender, s)`
    }
}

contract EventSniffSafe {
    event LeakHash(address indexed who, bytes32 secretHash);
    function store(uint256 s) external {
        emit LeakHash(msg.sender, keccak256(abi.encodePacked(s)));
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) MEMPOOL SNIFFING (Commit–Reveal)
//
//   * Vulnerable: reveal phase leaks secret in clear in mempool
//   * Attack: read tx‑pool for secret+salt before mining
//   * Defense: one‑time reveal; secret consumed on‑chain
// 
////////////////////////////////////////////////////////////////////////////////
contract MempoolSniffVuln {
    mapping(address => bytes32) public commitHash;
    function commit(bytes32 h) external {
        commitHash[msg.sender] = h;
    }
    function reveal(uint256 secret, bytes32 salt) external view returns (bool) {
        return keccak256(abi.encodePacked(secret, salt)) == commitHash[msg.sender];
    }
}

contract Attack_MempoolSniff {
    MempoolSniffVuln public target;
    bytes32          public salt;
    constructor(MempoolSniffVuln _t, bytes32 _salt) {
        target = _t; salt = _salt;
    }
    function commitSecret(uint256 s) external {
        target.commit(keccak256(abi.encodePacked(s, salt)));
    }
    function revealSecret(uint256 s) external view returns (bool) {
        return target.reveal(s, salt);
    }
}

contract MempoolSniffSafe {
    mapping(address => bytes32) public commitHash;
    mapping(address => bool)   public revealed;

    function commit(bytes32 h) external {
        commitHash[msg.sender] = h;
        revealed[msg.sender]  = false;
    }

    function reveal(uint256 secret, bytes32 salt) external {
        if (revealed[msg.sender]) revert Sniff__AlreadyRevealed();
        bytes32 h = keccak256(abi.encodePacked(secret, salt));
        if (h != commitHash[msg.sender]) revert Sniff__BadHash();
        revealed[msg.sender] = true;
        // secret consumed; cannot be re‑revealed
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) ORACLE SNIFFING
//
//   * Vulnerable: public oracle getter leaks data
//   * Attack: read any feed’s price via view()
//   * Defense: restrict updates to authorized oracles
// 
////////////////////////////////////////////////////////////////////////////////
contract OracleSniffVuln {
    mapping(address => uint256) public price;
    function updatePrice(uint256 p) external {
        price[msg.sender] = p;
    }
}

contract Attack_OracleSniff {
    OracleSniffVuln public target;
    constructor(OracleSniffVuln _t) { target = _t; }
    function sniffPrice(address feed) external view returns (uint256) {
        return target.price(feed);
    }
}

contract OracleSniffSafe {
    mapping(address => uint256) private _price;
    mapping(address => bool)    public isOracle;
    address public immutable     owner;

    error Oracle__NotOracle();

    constructor() {
        owner = msg.sender;
    }

    function setOracle(address oracle, bool allowed) external {
        require(msg.sender == owner, "Only owner");
        isOracle[oracle] = allowed;
    }

    function updatePrice(uint256 p) external {
        if (!isOracle[msg.sender]) revert Oracle__NotOracle();
        _price[msg.sender] = p;
    }

    function getPrice(address feed) external view returns (uint256) {
        return _price[feed];
    }
}
