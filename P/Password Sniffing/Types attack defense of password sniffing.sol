// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ======================= TYPES ======================= */

// 1️⃣ Calldata Sniffing
contract CalldataSniff {
    function login(string calldata password) external pure returns (bool) {
        return keccak256(bytes(password)) == keccak256("hunter2");
    }
}

// 2️⃣ Event Log Sniffing
contract EventLeak {
    event PasswordExposed(string pw);

    function set(string calldata pw) external {
        emit PasswordExposed(pw);
    }
}

// 3️⃣ Storage Variable Sniffing
contract ExposedStorage {
    string public exposed = "openpassword";
}

// 4️⃣ Commit-Reveal Reassembly
contract CommitReveal {
    bytes32 public commitment;

    function commit(bytes32 c) external {
        commitment = c;
    }

    function reveal(string calldata pw) external view returns (bool) {
        return keccak256(bytes(pw)) == commitment;
    }
}

// 5️⃣ Fallback + SigSniff Trap
contract FallbackSniff {
    event Sniffed(bytes data);

    fallback() external {
        emit Sniffed(msg.data); // trap caller's data
    }
}

/* ======================= ATTACKS ======================= */

// 1️⃣ Public Calldata Listener (Simulated)
contract CallSniffer {
    function decode(bytes calldata input) external pure returns (string memory) {
        (, string memory pw) = abi.decode(input[4:], (address, string));
        return pw;
    }
}

// 2️⃣ Event Listener Bot (off-chain)
contract EventSnifferBot {
    event Intercept(string leak);

    function sniff(string calldata pw) external {
        emit Intercept(pw);
    }
}

// 3️⃣ Storage Slot Scraper
contract StorageReader {
    function read(address target, uint256 slot) external view returns (bytes32 val) {
        assembly {
            extcodecopy(target, add(val, 32), slot, 32)
        }
    }
}

// 4️⃣ Replay & Reveal
contract ReplayReveal {
    function replay(address target, bytes calldata callData) external {
        target.call(callData);
    }
}

// 5️⃣ Log Decoding Proxy Trap
contract ProxySniffer {
    fallback() external payable {
        emit SniffedData(msg.data);
    }

    event SniffedData(bytes raw);
}

/* ======================= DEFENSES ======================= */

// 🛡️ 1 Hash Commitment
contract HashedLogin {
    bytes32 public commit;

    function set(string calldata pw, string calldata salt) external {
        commit = keccak256(abi.encodePacked(pw, salt));
    }

    function login(string calldata pw, string calldata salt) external view returns (bool) {
        return commit == keccak256(abi.encodePacked(pw, salt));
    }
}

// 🛡️ 2 Encoded Offchain Auth
contract EncodedAuth {
    bytes32 public ref;

    function set(bytes32 _hash) external {
        ref = _hash;
    }

    function verify(bytes calldata payload) external view returns (bool) {
        return keccak256(payload) == ref;
    }
}

// 🛡️ 3 No Logs Defense
contract SilentAuth {
    bytes32 public hashed;

    function login(string calldata pw) external {
        require(keccak256(bytes(pw)) == hashed);
        // no logs
    }
}

// 🛡️ 4 Slot Isolation
contract SlotGuarded {
    mapping(address => bytes32) private pwHash;

    function set(string calldata pw) external {
        pwHash[msg.sender] = keccak256(bytes(pw));
    }

    function validate(string calldata pw) external view returns (bool) {
        return pwHash[msg.sender] == keccak256(bytes(pw));
    }
}

// 🛡️ 5 zkProof Offchain Auth Stub
contract zkProofStub {
    bytes32 public trustedProof;

    function submitProof(bytes calldata pubInput) external view returns (bool) {
        return keccak256(pubInput) == trustedProof;
    }
}
