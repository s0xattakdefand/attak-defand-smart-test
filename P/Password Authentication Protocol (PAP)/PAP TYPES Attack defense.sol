// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ===================== TYPES ======================= */

// 1️⃣ Plaintext PAP
contract PlaintextPAP {
    string private storedPassword = "secret";

    function login(string calldata input) external view returns (bool) {
        return keccak256(bytes(input)) == keccak256(bytes(storedPassword));
    }
}

// 2️⃣ Hashed PAP
contract HashedPAP {
    bytes32 public immutable hash;

    constructor(string memory _pw) {
        hash = keccak256(bytes(_pw));
    }

    function login(string calldata pw) external view returns (bool) {
        return keccak256(bytes(pw)) == hash;
    }
}

// 3️⃣ Commitment PAP
contract CommitmentPAP {
    bytes32 public commitment;

    function setCommitment(bytes32 c) external {
        commitment = c;
    }

    function reveal(string calldata pw) external view returns (bool) {
        return keccak256(bytes(pw)) == commitment;
    }
}

// 4️⃣ Signature-based Auth
contract SigAuth {
    address public immutable validUser;

    constructor(address user) {
        validUser = user;
    }

    function login(string calldata msgText, bytes calldata sig) external pure returns (address) {
        bytes32 h = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", uint2str(bytes(msgText).length), msgText));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }

    function uint2str(uint _i) internal pure returns (string memory str) {
        if (_i == 0) return "0";
        uint j = _i;
        uint len;
        while (j != 0) { len++; j /= 10; }
        bytes memory bstr = new bytes(len);
        uint k = len;
        j = _i;
        while (j != 0) {
            bstr[--k] = bytes1(uint8(48 + j % 10));
            j /= 10;
        }
        str = string(bstr);
    }
}

// 5️⃣ Zero-Knowledge PAP (Mocked for Solidity)
contract ZKPAPMock {
    bytes32 public acceptedHash;

    function setAccepted(bytes32 h) external {
        acceptedHash = h;
    }

    function verifyProof(bytes calldata pubSignal) external view returns (bool) {
        return keccak256(pubSignal) == acceptedHash;
    }
}

/* ===================== ATTACKS ======================= */

// 1️⃣ Onchain Dictionary
contract DictionaryAttack {
    function brute(bytes32 targetHash, string[] calldata guesses) external pure returns (bool) {
        for (uint i = 0; i < guesses.length; i++) {
            if (keccak256(bytes(guesses[i])) == targetHash) return true;
        }
        return false;
    }
}

// 2️⃣ Front-Running Login Packet
contract FrontRunLogin {
    function replayLogin(bytes calldata payload, address target) external {
        target.call(payload);
    }
}

// 3️⃣ Storage Read Exposure
contract ExposedStorage {
    bytes32 public stored;

    constructor(string memory pw) {
        stored = keccak256(bytes(pw));
    }
}

// 4️⃣ Signature Replay
contract SigReplay {
    bytes32 public lastHash;

    function reuseSig(bytes32 h) external {
        require(h != lastHash, "Replay");
        lastHash = h;
    }
}

// 5️⃣ zkCommit Drift Injection
contract zkDrift {
    bytes32 public drifted;

    function submit(bytes calldata sig) external {
        drifted = keccak256(sig); // accept unvalidated
    }
}

/* ===================== DEFENSE ======================= */

// 🛡️ 1 Salted Hash Auth
contract SaltedHash {
    bytes32 public salted;

    constructor(string memory pw, string memory salt) {
        salted = keccak256(abi.encodePacked(pw, salt));
    }

    function check(string calldata pw, string calldata saltInput) external view returns (bool) {
        return keccak256(abi.encodePacked(pw, saltInput)) == salted;
    }
}

// 🛡️ 2 Time-Bound Nonce
contract NonceTimeGuard {
    mapping(address => uint256) public nonces;

    function login(bytes calldata data) external {
        require(block.timestamp > nonces[msg.sender], "Old login");
        nonces[msg.sender] = block.timestamp;
    }
}

// 🛡️ 3 Storage Masking
contract MaskedStorage {
    mapping(address => bytes32) private hidden;

    function set(bytes32 hash) external {
        hidden[msg.sender] = hash;
    }

    function get() external view returns (bytes32) {
        return hidden[msg.sender];
    }
}

// 🛡️ 4 Signature Nonce Guard
contract SigNonceGuard {
    mapping(bytes32 => bool) public used;

    function validate(bytes32 hash, bytes calldata sig) external {
        require(!used[hash], "Replay attempt");
        used[hash] = true;
        // validate signature offchain
    }
}

// 🛡️ 5 zkProof Binding
contract zkBoundProof {
    bytes32 public validBound;

    function set(bytes32 h) external {
        validBound = h;
    }

    function validate(bytes calldata pubSig) external view returns (bool) {
        return keccak256(pubSig) == validBound;
    }
}
