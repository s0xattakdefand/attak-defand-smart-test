// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

////////////////////////////////////////////////////////////////////////////////
//                            1) BASIC SERVER
////////////////////////////////////////////////////////////////////////////////
/// Vulnerable: no access control on update()
contract BasicServerVuln {
    uint256 public data;
    event DataUpdated(uint256 newData, address indexed who);

    function update(uint256 _data) external {
        data = _data;
        emit DataUpdated(_data, msg.sender);
    }
}

/// Attack: any attacker can call update()
contract Attack_BasicServer {
    BasicServerVuln public srv;
    constructor(BasicServerVuln _srv) { srv = _srv; }
    function hijack(uint256 fake) external {
        srv.update(fake); // succeeds, even though attacker isn’t “server”
    }
}

/// Safe: restrict update() to owner
contract BasicServerSafe {
    uint256 public data;
    address public immutable owner;
    event DataUpdated(uint256 newData);

    error NotOwner();

    constructor() { owner = msg.sender; }

    function update(uint256 _data) external {
        if (msg.sender != owner) revert NotOwner();
        data = _data;
        emit DataUpdated(_data);
    }
}

////////////////////////////////////////////////////////////////////////////////
//                      2) AUTHENTICATED SERVER
////////////////////////////////////////////////////////////////////////////////
library ECDSA {
    error InvalidSignature();
    function recover(bytes32 hash, bytes calldata sig) internal pure returns (address a) {
        if (sig.length != 65) revert InvalidSignature();
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        a = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)), v, r, s);
    }
}

/// Vulnerable: naive single‐sig update, no nonce/expiry
contract AuthServerVuln {
    uint256 public data;
    address public server;  // off‑chain signer

    event DataUpdated(uint256 newData);

    constructor(address _server) { server = _server; }

    // ❌ no replay protection!
    function update(uint256 _data, bytes calldata sig) external {
        bytes32 h = keccak256(abi.encodePacked(_data));
        if (ECDSA.recover(h, sig) != server) revert ECDSA.InvalidSignature();
        data = _data;
        emit DataUpdated(_data);
    }
}

/// Attack: replay the same signed message over and over
contract Attack_AuthReplay {
    AuthServerVuln public srv;
    uint256 public fake;
    bytes   public sig;
    constructor(AuthServerVuln _srv, uint256 _fake, bytes memory _sig) {
        srv  = _srv;
        fake = _fake;
        sig  = _sig;
    }
    function replay() external {
        srv.update(fake, sig); // always succeeds (no nonce / expiry)
    }
}

/// Safe: single‐sig + nonce + expiry
contract AuthServerSafe {
    using ECDSA for bytes32;

    uint256 public data;
    address public immutable server;
    mapping(uint256 => bool) public usedNonce;

    error BadSig();
    error Expired();
    error NonceUsed();

    event DataUpdated(uint256 newData, uint256 indexed nonce);

    constructor(address _server) { server = _server; }

    function update(
        uint256 _data,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        if (block.timestamp > expiry)        revert Expired();
        if (usedNonce[nonce])                revert NonceUsed();

        bytes32 h = keccak256(abi.encodePacked(_data, nonce, expiry));
        if (ECDSA.recover(h, sig) != server) revert BadSig();

        usedNonce[nonce] = true;
        data = _data;
        emit DataUpdated(_data, nonce);
    }
}

////////////////////////////////////////////////////////////////////////////////
//                         3) MULTI‑SIG SERVER
////////////////////////////////////////////////////////////////////////////////
error MultiSig__BadSig();
error MultiSig__Threshold();
error MultiSig__Replayed();

contract MultiSigServerSafe {
    using ECDSA for bytes32;

    uint256 public data;
    address[] public signers;
    uint256 public immutable THRESHOLD;
    mapping(bytes32 => bool) public executed;

    bytes32 public immutable DOMAIN;

    event DataUpdated(uint256 newData, bytes32 indexed txHash);

    constructor(address[] memory _signers, uint256 _k) {
        require(_k > 0 && _k <= _signers.length, "k invalid");
        signers   = _signers;
        THRESHOLD = _k;
        DOMAIN    = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
                keccak256("MultiSigServerSafe"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @notice Update with k-of-n signatures
    function update(
        uint256 _data,
        uint256 nonce,
        uint256 expiry,
        bytes[] calldata sigs
    ) external {
        require(block.timestamp <= expiry, "Expired");

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Update(uint256 data,uint256 nonce,uint256 expiry)"),
            _data, nonce, expiry
        ));
        bytes32 txHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (executed[txHash]) revert MultiSig__Replayed();

        // verify k sorted sigs
        address last;
        uint256 count;
        for (uint i; i < sigs.length; i++) {
            address signer = txHash.recover(sigs[i]);
            require(signer > last, "unordered/dup");
            last = signer;
            // check signer in list
            bool ok;
            for (uint j; j < signers.length; j++) if (signers[j] == signer) { ok = true; break; }
            if (!ok) revert MultiSig__BadSig();
            count++;
        }
        if (count < THRESHOLD) revert MultiSig__Threshold();

        executed[txHash] = true;
        data = _data;
        emit DataUpdated(_data, txHash);
    }
}

/// Attack: provide < k signatures → revert
contract Attack_MultiSigFail {
    MultiSigServerSafe public srv;
    constructor(MultiSigServerSafe _srv) { srv = _srv; }
    function fail(uint256 fake, uint256 nonce, uint256 exp, bytes[] calldata sigs) external {
        srv.update(fake, nonce, exp, sigs); // reverts if sigs.length < k
    }
}
