// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== PHARMING ATTACK SIMULATORS ========== */

// 1️⃣ Fake ENS Redirect
contract FakeENS {
    mapping(string => address) public names;

    function register(string calldata name, address target) external {
        names[name] = target;
    }

    function resolve(string calldata name) external view returns (address) {
        return names[name]; // could be attacker!
    }
}

// 2️⃣ Proxy Slot Override
contract ProxyPharming {
    address public logic;

    fallback() external {
        (bool ok, ) = logic.delegatecall(msg.data);
        require(ok);
    }

    function overrideLogic(address newLogic) external {
        logic = newLogic; // attacker can redirect here
    }
}

// 3️⃣ UI Signature Drift
contract SigDriftPharmer {
    function relay(address target, bytes32 h, bytes calldata sig) external {
        (bool ok, ) = target.call(abi.encodeWithSignature("login(bytes32,bytes)", h, sig));
        require(ok);
    }
}

// 4️⃣ Oracle Pharming
contract OraclePoison {
    address public dataSource;

    function setSource(address o) external {
        dataSource = o;
    }

    function fetch() external view returns (uint256) {
        return IOracle(dataSource).get();
    }
}

interface IOracle {
    function get() external view returns (uint256);
}

// 5️⃣ Metadata Redirect
contract NFTMetadataPharming {
    mapping(uint256 => string) public metadata;

    function setURI(uint256 id, string calldata uri) external {
        metadata[id] = uri;
    }

    function uri(uint256 id) external view returns (string memory) {
        return metadata[id];
    }
}

/* ========== PHARMING DEFENSE MODULES ========== */

// 🛡️ 1 ENS Binding Guard
contract RegistryHashGuard {
    bytes32 public trustedHash;

    function setTrusted(bytes32 h) external {
        trustedHash = h;
    }

    function verifyName(string calldata name, address resolved) external view returns (bool) {
        return keccak256(abi.encodePacked(name, resolved)) == trustedHash;
    }
}

// 🛡️ 2 Proxy Lock Guard
contract ProxyGuard {
    address public logic;
    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "Access Denied");
        _;
    }

    function upgrade(address newLogic) external onlyAdmin {
        logic = newLogic;
    }

    fallback() external {
        (bool ok, ) = logic.delegatecall(msg.data);
        require(ok);
    }
}

// 🛡️ 3 EIP-712 Sig Firewall
contract DomainBoundSig {
    bytes32 public domainSeparator;

    constructor(string memory name, string memory version) {
        domainSeparator = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256(bytes(name)),
            keccak256(bytes(version))
        ));
    }

    function recover(bytes32 structHash, bytes calldata sig) external view returns (address) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(digest, v, r, s);
    }
}

// 🛡️ 4 Oracle Source Whitelist
contract OracleWhitelist {
    mapping(address => bool) public trusted;

    function trust(address src, bool y) external {
        trusted[src] = y;
    }

    function get(address o) external view returns (uint256) {
        require(trusted[o], "Untrusted Oracle");
        return IOracle(o).get();
    }
}

// 🛡️ 5 Metadata Hash Guard
contract MetadataIntegrity {
    mapping(uint256 => bytes32) public metaHash;

    function storeHash(uint256 tokenId, string calldata uri) external {
        metaHash[tokenId] = keccak256(bytes(uri));
    }

    function validate(uint256 id, string calldata uri) external view returns (bool) {
        return keccak256(bytes(uri)) == metaHash[id];
    }
}
