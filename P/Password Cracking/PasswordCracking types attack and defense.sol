// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ==================== TYPES ==================== */

// 1️⃣ Brute Force
contract BruteForcePoc {
    bytes32 public hash;

    constructor(string memory pw) {
        hash = keccak256(bytes(pw));
    }

    function guess(string calldata attempt) external view returns (bool) {
        return keccak256(bytes(attempt)) == hash;
    }
}

// 2️⃣ Dictionary Attack
contract DictionaryChecker {
    bytes32 public target;

    constructor(string memory word) {
        target = keccak256(bytes(word));
    }

    function matchList(string[] calldata list) external view returns (bool) {
        for (uint i = 0; i < list.length; i++) {
            if (keccak256(bytes(list[i])) == target) return true;
        }
        return false;
    }
}

// 3️⃣ Preimage Attack
contract PreimageTarget {
    bytes32 public goal;

    constructor(bytes32 g) {
        goal = g;
    }

    function crack(bytes calldata attempt) external view returns (bool) {
        return keccak256(attempt) == goal;
    }
}

// 4️⃣ Rainbow Table Attack
contract RainbowSim {
    mapping(bytes32 => string) public precomputed;

    function load(string calldata pw) external {
        precomputed[keccak256(bytes(pw))] = pw;
    }

    function reveal(bytes32 hash) external view returns (string memory) {
        return precomputed[hash];
    }
}

// 5️⃣ Replay Signature Drift
contract ReplayLogin {
    mapping(address => uint256) public nonces;

    function login(bytes32 hash, bytes calldata sig, uint256 nonce) external {
        require(nonce > nonces[msg.sender], "Replay");
        nonces[msg.sender] = nonce;
        // Assume signature checked off-chain
    }
}

/* ==================== ATTACKS ==================== */

// 1️⃣ Onchain Brute Force
contract BruteCracker {
    function test(bytes32 target, string[] calldata list) external pure returns (string memory) {
        for (uint i = 0; i < list.length; i++) {
            if (keccak256(bytes(list[i])) == target) return list[i];
        }
        return "";
    }
}

// 2️⃣ Commit-Reveal Scanner
contract CommitRevealSniffer {
    function sniff(bytes32 commitment, string calldata pw) external pure returns (bool) {
        return keccak256(bytes(pw)) == commitment;
    }
}

// 3️⃣ Gas-Efficient Crack Loop
contract GasCracker {
    function loop(bytes32 target) external pure returns (bool found) {
        for (uint i = 0; i < 128; i++) {
            if (keccak256(abi.encodePacked(i)) == target) return true;
        }
    }
}

// 4️⃣ Signature Fuzzer
contract SigFuzzer {
    function fuzz(bytes32 hash, bytes calldata sig) external pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

// 5️⃣ Login Replay Injector
contract LoginInjector {
    function replay(address target, bytes calldata loginPayload) external {
        (bool ok, ) = target.call(loginPayload);
        require(ok);
    }
}

/* ==================== DEFENSE ==================== */

// 🛡️ 1 Rate Limiter Guard
contract RateLimiter {
    mapping(address => uint256) public lastTry;

    function check() external {
        require(block.timestamp > lastTry[msg.sender] + 10, "Rate limit");
        lastTry[msg.sender] = block.timestamp;
    }
}

// 🛡️ 2 Salted Commitment
contract SaltedCommitment {
    bytes32 public commit;

    function setCommit(string memory pw, string memory salt) public {
        commit = keccak256(abi.encodePacked(pw, salt));
    }

    function verify(string calldata pw, string calldata salt) public view returns (bool) {
        return keccak256(abi.encodePacked(pw, salt)) == commit;
    }
}

// 🛡️ 3 Preimage Expiry Guard
contract ExpiringSecret {
    bytes32 public hash;
    uint256 public validUntil;

    function set(string calldata pw, uint256 expireTime) external {
        hash = keccak256(bytes(pw));
        validUntil = block.timestamp + expireTime;
    }

    function check(string calldata pw) external view returns (bool) {
        require(block.timestamp <= validUntil, "Expired");
        return keccak256(bytes(pw)) == hash;
    }
}

// 🛡️ 4 Sig Nonce Guard
contract SigNonce {
    mapping(bytes32 => bool) public used;

    function validate(bytes32 hash) public {
        require(!used[hash], "Nonce used");
        used[hash] = true;
    }
}

// 🛡️ 5 Offchain Proof Stub
contract OffchainVerifier {
    event AuthAttempt(bytes32 hash, address user);

    function submit(bytes32 pwHash) external {
        emit AuthAttempt(pwHash, msg.sender);
        // Validate offchain (zk/server/oracle)
    }
}
