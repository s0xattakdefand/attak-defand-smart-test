// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

////////////////////////////////////////////////////////////////////////
//                              ERRORS
////////////////////////////////////////////////////////////////////////
error Sniffer__NotAuthorized();
error Sniffer__BadHash();
error Sniffer__AlreadyRevealed();
error Sniffer__NoCommit();

////////////////////////////////////////////////////////////////////////
// 1) STORAGE SNIFFER
//    Public storage leaks private data
////////////////////////////////////////////////////////////////////////
contract StorageSnifferVuln {
    mapping(address => uint256) public secret;

    function setSecret(uint256 s) external {
        secret[msg.sender] = s;
    }
}

/// Anyone can call and read another user’s secret!
contract Attack_StorageSniffer {
    StorageSnifferVuln public target;
    constructor(StorageSnifferVuln _t) { target = _t; }

    function sniff(address user) external view returns (uint256) {
        return target.secret(user);
    }
}

contract StorageSnifferSafe {
    mapping(address => uint256) private secret;
    event SecretUpdated(address indexed who);

    function setSecret(uint256 s) external {
        secret[msg.sender] = s;
        emit SecretUpdated(msg.sender);
    }

    /// Only the owner can verify their own secret
    function verifySecret(uint256 s) external view returns (bool) {
        return secret[msg.sender] == s;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) EVENT SNIFFER
//    Emitting plaintext in events leaks it to off‑chain observers
////////////////////////////////////////////////////////////////////////
contract EventSnifferVuln {
    event Leak(address indexed who, uint256 secret);

    function store(uint256 s) external {
        emit Leak(msg.sender, s);
    }
}

/// “Attack” here is simply listening to the logs off‑chain after `store()`.
/// But we include a helper that triggers the leak.
contract Attack_EventSniffer {
    EventSnifferVuln public target;
    constructor(EventSnifferVuln _t) { target = _t; }

    function storeAndLeak(uint256 s) external {
        target.store(s);
    }
}

contract EventSnifferSafe {
    event LeakHash(address indexed who, bytes32 secretHash);

    function store(uint256 s) external {
        emit LeakHash(msg.sender, keccak256(abi.encodePacked(s)));
    }
}

////////////////////////////////////////////////////////////////////////
// 3) MEMPOOL SNIFFER (Commit–Reveal)
//    Immediate reveal is sniffable in the tx pool before mining
////////////////////////////////////////////////////////////////////////
contract CommitRevealVuln {
    mapping(address => bytes32) public commitHash;

    /// Commit hash = keccak256(abi.encodePacked(secret, salt))
    function commit(bytes32 h) external {
        commitHash[msg.sender] = h;
    }

    /// Reveal freely; secret + salt is visible in the clear in mempool
    function reveal(uint256 secret, bytes32 salt) external view returns (bool) {
        return keccak256(abi.encodePacked(secret, salt)) == commitHash[msg.sender];
    }
}

/// Demonstrates committing and then revealing your secret (sniffable off‑chain).
contract Attack_MempoolSniffer {
    CommitRevealVuln public target;
    bytes32          public salt;
    constructor(CommitRevealVuln _t, bytes32 _salt) {
        target = _t;
        salt   = _salt;
    }

    function commitSecret(uint256 s) external {
        target.commit(keccak256(abi.encodePacked(s, salt)));
    }
    function revealSecret(uint256 s) external view returns (bool) {
        return target.reveal(s, salt);
    }
}

contract CommitRevealSafe {
    mapping(address => bytes32) public commitHash;
    mapping(address => bool)   public revealed;

    /// Commit phase
    function commit(bytes32 h) external {
        commitHash[msg.sender] = h;
        revealed[msg.sender]  = false;
    }

    /// Reveal only once; after that the secret cannot be re‑revealed
    function reveal(uint256 secret, bytes32 salt) external {
        if (revealed[msg.sender]) revert Sniffer__AlreadyRevealed();
        bytes32 h = keccak256(abi.encodePacked(secret, salt));
        if (h != commitHash[msg.sender]) revert Sniffer__BadHash();
        revealed[msg.sender] = true;
        // secret is now “consumed” on‑chain; no further reveal allowed
    }
}

////////////////////////////////////////////////////////////////////////
// 4) ORACLE SNIFFER
//    Unrestricted feeds allow anyone to publish or read sensitive on‑chain data
////////////////////////////////////////////////////////////////////////
contract OracleSnifferVuln {
    mapping(address => uint256) public price;

    /// Anyone can set any price for any feed
    function updatePrice(uint256 p) external {
        price[msg.sender] = p;
    }
}

/// Attack can simply read `price(feedAddress)` off‑chain or via a view
contract Attack_OracleSniffer {
    OracleSnifferVuln public target;
    constructor(OracleSnifferVuln _t) { target = _t; }

    function sniffPrice(address feed) external view returns (uint256) {
        return target.price(feed);
    }
}

contract OracleSnifferSafe {
    mapping(address => uint256) private price;
    mapping(address => bool)    public isOracle;
    address public immutable     owner;

    error Oracle__NotOracle();

    constructor() { owner = msg.sender; }

    /// Only owner can designate authorized oracles
    function setOracle(address oracle, bool allowed) external {
        require(msg.sender == owner, "Only owner");
        isOracle[oracle] = allowed;
    }

    /// Only an authorized oracle may push updates
    function updatePrice(uint256 p) external {
        if (!isOracle[msg.sender]) revert Oracle__NotOracle();
        price[msg.sender] = p;
    }

    function getPrice(address feed) external view returns (uint256) {
        return price[feed];
    }
}
