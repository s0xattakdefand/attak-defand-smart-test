// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Shared errors
error SI__Unauthorized();
error SI__InvalidSignature();

/// @dev Simple ECDSA recover for "\x19Ethereum Signed Message:\n32"+hash
library SigLib {
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert SI__InvalidSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h)), v, r, s);
    }
}

/*//////////////////////////////////////////////////////////////////////
// 1. HARDCODED SECRETS
//////////////////////////////////////////////////////////////////////*/
/// Vulnerable: secret baked into bytecode (private ≠ hidden)
contract HardcodedSecretVuln {
    string private constant API_KEY = "SUPER_SECRET_API_KEY";
    /// @notice Returns the secret (simulates misuse)
    function getApiKey() external pure returns (string memory) {
        return API_KEY;
    }
}

/// Attack: simply calls and reads the API key
contract Attack_HardcodedSecret {
    HardcodedSecretVuln public target;
    constructor(HardcodedSecretVuln _t) { target = _t; }
    function stealKey() external view returns (string memory) {
        return target.getApiKey();
    }
}

/// Safe: no on‑chain secret—require off‑chain signed auth
contract HardcodedSecretSafe {
    using SigLib for bytes32;
    address public immutable manager;
    bytes32 public constant AUTH_TYPEHASH = keccak256("Auth(address who)");

    constructor(address _manager) {
        manager = _manager;
    }

    /// @notice Only a message signed by `manager` can trigger this
    function privilegedAction(bytes calldata sig) external {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encode(AUTH_TYPEHASH, msg.sender))
        ));
        if (digest.recover(sig) != manager) revert SI__Unauthorized();
        // … perform sensitive work off‑chain or emit an event …
    }
}

/*//////////////////////////////////////////////////////////////////////
// 2. UNENCRYPTED STORAGE OF PII
//////////////////////////////////////////////////////////////////////*/
/// Vulnerable: stores raw SSN and exposes via view()
contract StorageLeakVuln {
    uint256 public ssn;
    constructor(uint256 _ssn) {
        ssn = _ssn;
    }
}

/// Attack: reads `ssn` directly
contract Attack_StorageLeak {
    StorageLeakVuln public target;
    constructor(StorageLeakVuln _t) { target = _t; }
    function readSSN() external view returns (uint256) {
        return target.ssn();
    }
}

/// Safe: only store hash; provide verifier
contract StorageEncryptSafe {
    bytes32 private immutable ssnHash;

    constructor(bytes32 _ssnHash) {
        ssnHash = _ssnHash;
    }

    /// @notice Verifies user‑provided SSN matches stored hash
    function verifySSN(uint256 _ssn) external view returns (bool) {
        return keccak256(abi.encodePacked(_ssn)) == ssnHash;
    }
}

/*//////////////////////////////////////////////////////////////////////
// 3. EVENT LEAKAGE OF SENSITIVE DATA
//////////////////////////////////////////////////////////////////////*/
/// Vulnerable: emits plaintext SSN in logs
contract EventLeakVuln {
    event SSNEmitted(uint256 indexed ssn);
    function logSSN(uint256 _ssn) external {
        emit SSNEmitted(_ssn);
    }
}

/// Attack: watch logs for SSNEmitted events
contract Attack_EventLeak {
    EventLeakVuln public target;
    constructor(EventLeakVuln _t) { target = _t; }
    function leak(uint256 _ssn) external {
        target.logSSN(_ssn);
    }
}

/// Safe: emit only hash of SSN
contract EventHashSafe {
    event SSNHashEmitted(bytes32 indexed ssnHash);
    function logSSN(uint256 _ssn) external {
        emit SSNHashEmitted(keccak256(abi.encodePacked(_ssn)));
    }
}

/*//////////////////////////////////////////////////////////////////////
// 4. ORACLE DATA LEAK
//////////////////////////////////////////////////////////////////////*/
/// Minimal Oracle interface
interface IOracle {
    function getData() external view returns (string memory);
}

/// Vulnerable Oracle: returns raw sensitive data to anyone
contract OracleLeakVuln is IOracle {
    string private data;
    constructor(string memory _data) {
        data = _data;
    }
    function getData() external view override returns (string memory) {
        return data;
    }
}

/// Attack: simply calls `getData()`
contract Attack_OracleLeak {
    OracleLeakVuln public target;
    constructor(OracleLeakVuln _t) { target = _t; }
    function leakData() external view returns (string memory) {
        return target.getData();
    }
}

/// Safe Oracle: restrict reads to a whitelist
contract OracleAuthSafe is IOracle {
    string private data;
    mapping(address => bool) public allowed;

    error Oracle__NotAllowed();

    constructor(string memory _data, address[] memory _allowed) {
        data = _data;
        for (uint i; i < _allowed.length; i++) {
            allowed[_allowed[i]] = true;
        }
    }

    function getData() external view override returns (string memory) {
        if (!allowed[msg.sender]) revert Oracle__NotAllowed();
        return data;
    }
}
