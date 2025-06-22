// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== ATTACK SIMULATORS ========== */

// 1️⃣ Storage Recon
contract PlaintextStorage {
    string public secret = "plaintext-secret"; // easily recon-ed
}

// 2️⃣ Calldata Echo
contract Echo {
    event Echoed(string msg);

    function echo(string calldata msg_) external {
        emit Echoed(msg_); // leaked to logs
    }
}

// 3️⃣ Plaintext Commitment (broken)
contract CommitBroken {
    string public committedValue;

    function commit(string calldata val) external {
        committedValue = val; // not hashed
    }
}

// 4️⃣ Signature Replay (plaintext)
contract ReplaySig {
    function validate(bytes32 hash, bytes calldata sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s); // no domain bind
    }
}

// 5️⃣ Calldata Replayer
contract Recaller {
    function ping(string calldata m) external pure returns (string memory) {
        return m; // can replay known calldata
    }
}

/* ========== DEFENSE MODULES ========== */

// 🛡️ 1 Keccak256 Storage Protection
contract HashedStorage {
    bytes32 public hashed;

    function store(string calldata secret) external {
        hashed = keccak256(abi.encodePacked(secret));
    }

    function verify(string calldata guess) external view returns (bool) {
        return keccak256(abi.encodePacked(guess)) == hashed;
    }
}

// 🛡️ 2 Commit-Reveal with Salt Binding
contract SecureCommit {
    mapping(address => bytes32) public commits;

    function commit(bytes32 c) external {
        commits[msg.sender] = c;
    }

    function reveal(string calldata val, string calldata salt) external view returns (bool) {
        return commits[msg.sender] == keccak256(abi.encodePacked(val, salt));
    }
}

// 🛡️ 3 EIP-712 Signature Bound
contract DomainBoundSig {
    bytes32 public DOMAIN;

    constructor(string memory name, string memory version) {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256(bytes(name)),
            keccak256(bytes(version))
        ));
    }

    function validate(bytes32 structHash, bytes calldata sig) public view returns (address) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(digest, v, r, s);
    }
}

// 🛡️ 4 Log Filtering
contract LogSafe {
    event Safe(uint256 hashedPart);

    function log(string calldata s) external {
        emit Safe(uint256(keccak256(bytes(s)))); // hash before emit
    }
}

// 🛡️ 5 Access-Controlled Secret Storage
contract SecureStorage {
    bytes32 private stored;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function store(bytes32 h) external {
        require(msg.sender == owner, "No access");
        stored = h;
    }

    function get() external view returns (bytes32) {
        require(msg.sender == owner, "No access");
        return stored;
    }
}
