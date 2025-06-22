// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SwitchNetworkSuite.sol
/// @notice Four on‑chain “switch network” patterns illustrating common
///         pitfalls when relying on chain identifiers, plus hardened defenses.

error SN__Replayed();
error SN__WrongChain();

library ECDSALib {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes memory sig) internal pure returns (address a) {
        require(sig.length == 65, "ECDSA: bad length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0, mload(add(sig,96)))
        }
        a = ecrecover(h, v, r, s);
        require(a != address(0), "ECDSA: invalid");
    }
}

////////////////////////////////////////////////////////////////////////////////
// 1) Hardcoded ChainID Caching
//
//    • Type: cache block.chainid in constructor only once.
//    • Attack: after a chain‑split or switch, getChain() returns stale ID.
//    • Defense: always read block.chainid dynamically.
////////////////////////////////////////////////////////////////////////////////
contract HardcodedChainIDVuln {
    uint256 public cachedChain;
    constructor() {
        // only called at deployment
        cachedChain = block.chainid;
    }
    function getChain() external view returns (uint256) {
        // stale if network forked or switched
        return cachedChain;
    }
}

contract Attack_ChainIDSwitch {
    HardcodedChainIDVuln public target;
    constructor(HardcodedChainIDVuln _t) { target = _t; }
    function sniff() external view returns (uint256 actual, uint256 cached) {
        // actual may differ on a forked network
        return (block.chainid, target.getChain());
    }
}

contract HardcodedChainIDSafe {
    function getChain() external view returns (uint256) {
        // always current
        return block.chainid;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) EIP‑712 Domain Missing ChainID
//
//    • Type: domain omits chainId → signatures replayable across networks.
//    • Attack: sign on one network, replay on another.
//    • Defense: include block.chainid in domain separator.
////////////////////////////////////////////////////////////////////////////////
contract EIP712NoChainVuln {
    using ECDSALib for bytes32;
    bytes32 public DOMAIN; // only name/version
    bytes32 private constant TYPEHASH = keccak256("Exec(bytes payload,uint256 nonce)");

    mapping(uint256=>bool) public used;
    event Executed(address signer, bytes payload, uint256 nonce);

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256("Vuln"), keccak256("1")
        ));
    }

    function exec(
        bytes calldata payload,
        uint256       nonce,
        bytes calldata sig
    ) external {
        require(!used[nonce], "replayed");
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, keccak256(payload), nonce));
        bytes32 digest     = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer     = digest.recover(sig);
        used[nonce] = true;
        (bool ok,) = address(this).call(payload);
        require(ok);
        emit Executed(signer, payload, nonce);
    }
}

contract Attack_EIP712CrossNetwork {
    EIP712NoChainVuln public a;
    EIP712NoChainVuln public b;
    bytes             public payload;
    uint256           public nonce;
    bytes             public sig;

    constructor(
        EIP712NoChainVuln _a,
        EIP712NoChainVuln _b,
        bytes memory _p,
        uint256 _n,
        bytes memory _s
    ) {
        a = _a; b = _b; payload = _p; nonce = _n; sig = _s;
    }

    function cross() external {
        // signature valid on chain A also works on chain B
        b.exec(payload, nonce, sig);
    }
}

contract EIP712WithChainSafe {
    using ECDSALib for bytes32;
    bytes32 public DOMAIN;
    bytes32 private constant TYPEHASH = keccak256("Exec(bytes payload,uint256 nonce)");

    mapping(uint256=>bool) public used;
    event Executed(address signer, bytes payload, uint256 nonce);

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("Safe"), keccak256("1"), block.chainid, address(this)
        ));
    }

    function exec(
        bytes calldata payload,
        uint256       nonce,
        bytes calldata sig
    ) external {
        require(!used[nonce], "replayed");
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, keccak256(payload), nonce));
        bytes32 digest     = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer     = digest.recover(sig);
        used[nonce] = true;
        (bool ok,) = address(this).call(payload);
        require(ok);
        emit Executed(signer, payload, nonce);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) Meta‑Tx Replay Across Networks
//
//    • Type: meta‑transaction signature omits chainId → replayable on other chains.
//    • Attack: replay a relayed tx on a forked network.
//    • Defense: incorporate block.chainid into the signed data.
////////////////////////////////////////////////////////////////////////////////
contract MetaTxVuln {
    using ECDSALib for bytes32;
    event Executed(address from, bytes payload);

    function execRelayed(
        address from,
        bytes calldata payload,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(from, payload))
            .toEthSignedMessageHash();
        require(h.recover(sig) == from, "bad sig");
        (bool ok,) = address(this).call(payload);
        require(ok);
        emit Executed(from, payload);
    }
}

contract Attack_MetaTxCrossNetwork {
    MetaTxVuln public target;
    address        public from;
    bytes          public payload;
    bytes          public sig;
    constructor(MetaTxVuln _t, address _from, bytes memory _p, bytes memory _s){
        target = _t; from = _from; payload = _p; sig = _s;
    }
    function replay() external {
        // replay meta‑tx on another chain
        target.execRelayed(from, payload, sig);
    }
}

contract MetaTxSafe {
    using ECDSALib for bytes32;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("MetaTx(address from,bytes payload,uint256 nonce,uint256 expiry)");

    mapping(uint256=>bool) public used;

    event Executed(address from, bytes payload, uint256 nonce);

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("MetaSafe"), block.chainid, address(this)
        ));
    }

    function execRelayed(
        address from,
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "expired");
        require(!used[nonce], "replayed");

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, from, keccak256(payload), nonce, expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        require(digest.recover(sig) == from, "bad sig");

        used[nonce] = true;
        (bool ok,) = address(this).call(payload);
        require(ok);
        emit Executed(from, payload, nonce);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) Network‑Restricted Functionality
//
//    • Type: feature available only on a specific chain, but no check → can be
//             invoked on unintended networks.
//    • Attack: call on wrong network and bypass intended gating.
//    • Defense: require block.chainid == allowedChain.
////////////////////////////////////////////////////////////////////////////////
contract NetworkRestrictedVuln {
    function onlyOnMainnet() external pure returns (string memory) {
        // ❌ no chain check
        return "mainnet feature";
    }
}

contract Attack_NetworkRestricted {
    NetworkRestrictedVuln public target;
    constructor(NetworkRestrictedVuln _t) { target = _t; }
    function exploit() external view returns (string memory) {
        // still works on any chain
        return target.onlyOnMainnet();
    }
}

contract NetworkRestrictedSafe {
    uint256 public constant ALLOWED_CHAIN = 1; // Ethereum Mainnet
    error SN__WrongChain();

    function onlyOnMainnet() external view returns (string memory) {
        if (block.chainid != ALLOWED_CHAIN) revert SN__WrongChain();
        return "mainnet feature";
    }
}
