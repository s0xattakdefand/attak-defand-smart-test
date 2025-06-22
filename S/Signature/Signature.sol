// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

///─────────────────────────────────────────────────────────────────────────────
///                             ECDSA LIBRARY
///─────────────────────────────────────────────────────────────────────────────
library ECDSALib {
    /// @dev prefix & hash for eth_sign
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    /// @dev recover address from 65‑byte signature
    function recover(bytes32 h, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig,32))
            s := mload(add(sig,64))
            v := byte(0, mload(add(sig,96)))
        }
        address a = ecrecover(h, v, r, s);
        require(a != address(0), "ECDSA: invalid");
        return a;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) RAW ECDSA EXEC (Vulnerable vs Safe)
///─────────────────────────────────────────────────────────────────────────────
contract RawSignatureVuln {
    using ECDSALib for bytes32;
    event Executed(address signer, bytes payload);

    /// ❌ no replay protection
    function exec(bytes calldata payload, bytes calldata sig) external {
        bytes32 h = keccak256(payload).toEthSignedMessageHash();
        address signer = h.recover(sig);
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(signer, payload);
    }
}
contract Attack_RawSignatureReplay {
    RawSignatureVuln public target;
    bytes           public payload;
    bytes           public sig;
    constructor(RawSignatureVuln _t, bytes memory _payload, bytes memory _sig) {
        target  = _t;
        payload = _payload;
        sig     = _sig;
    }
    function replay() external {
        target.exec(payload, sig);
        target.exec(payload, sig); // succeeds again
    }
}

contract RawSignatureSafe {
    using ECDSALib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Exec(bytes payload,uint256 nonce,uint256 expiry)");

    mapping(uint256 => bool) public used;

    event Executed(address signer, bytes payload, uint256 nonce);

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("RawSignatureSafe"), block.chainid, address(this)
        ));
    }

    function exec(
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "expired");
        require(!used[nonce],             "replayed");

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, keccak256(payload), nonce, expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer = digest.recover(sig);

        used[nonce] = true;
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(signer, payload, nonce);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) EIP‑712 TYPED DATA (Vulnerable vs Safe)
///─────────────────────────────────────────────────────────────────────────────
contract EIP712Vuln {
    using ECDSALib for bytes32;
    // ❌ domain only includes name
    bytes32 public DOMAIN = keccak256(abi.encode(
        keccak256("EIP712Domain(string name)"),
        keccak256("Vuln")
    ));
    bytes32 private constant TYPEHASH =
        keccak256("Exec(bytes payload,uint256 nonce)");

    event Executed(address signer, bytes payload);

    function exec(
        bytes calldata payload,
        uint256       nonce,
        bytes calldata sig
    ) external {
        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, keccak256(payload), nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer = digest.recover(sig);
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(signer, payload);
    }
}
contract Attack_EIP712Collision {
    EIP712Vuln public a;
    EIP712Vuln public b;
    bytes       public payload;
    uint256     public nonce;
    bytes       public sig;
    constructor(
        EIP712Vuln _a,
        EIP712Vuln _b,
        bytes memory _p,
        uint256 _n,
        bytes memory _s
    ) {
        a = _a; b = _b;
        payload = _p; nonce = _n; sig = _s;
    }
    function cross() external {
        // replay on b with signature for a
        b.exec(payload, nonce, sig);
    }
}

contract EIP712Safe {
    using ECDSALib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Exec(bytes payload,uint256 nonce)");

    mapping(uint256 => bool) public used;

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

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, keccak256(payload), nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer = digest.recover(sig);

        used[nonce] = true;
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(signer, payload, nonce);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) MULTI‑SIG (k-of-n) (Vulnerable vs Safe)
///─────────────────────────────────────────────────────────────────────────────
contract MultiSigVuln {
    using ECDSALib for bytes32;

    address[] public signers;
    uint256   public threshold;

    constructor(address[] memory _s, uint256 _k) {
        require(_k>0 && _k<=_s.length,"bad k");
        signers   = _s;
        threshold = _k;
    }

    /// ❌ no nonce/expiry → replayable
    function exec(bytes calldata payload, bytes[] calldata sigs) external {
        bytes32 h = keccak256(payload).toEthSignedMessageHash();
        address last;
        uint256 count;
        for(uint i; i<sigs.length; i++){
            address s = h.recover(sigs[i]);
            require(s>last,"dup/unordered");
            last = s;
            bool ok;
            for(uint j; j<signers.length; j++){
                if(signers[j]==s){ ok = true; break; }
            }
            require(ok,"bad sig");
            count++;
        }
        require(count>=threshold,"threshold");
        (bool success,) = address(this).call(payload);
        require(success,"exec failed");
    }
}
contract Attack_MultiSigReplay {
    MultiSigVuln public target;
    bytes[]      public sigs;
    bytes        public payload;
    constructor(MultiSigVuln _t, bytes memory _p, bytes[] memory _sigs){
        target  = _t; payload = _p; sigs = _sigs;
    }
    function replay() external {
        target.exec(payload, sigs);
        target.exec(payload, sigs);
    }
}

contract MultiSigSafe {
    using ECDSALib for bytes32;

    address[] public signers;
    uint256   public immutable threshold;
    bytes32   public immutable DOMAIN;
    mapping(bytes32=>bool) public done;

    event Executed(bytes payload, bytes32 txHash);

    constructor(address[] memory _s, uint256 _k){
        require(_k>0 && _k<=_s.length,"bad k");
        signers   = _s;
        threshold = _k;
        DOMAIN    = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("MSafe"), block.chainid, address(this)
        ));
    }

    function exec(
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes[] calldata sigs
    ) external {
        require(block.timestamp<=expiry,"expired");

        bytes32 structHash = keccak256(abi.encode(
            keccak256("Exec(bytes payload,uint256 nonce,uint256 expiry)"),
            keccak256(payload), nonce, expiry
        ));
        bytes32 txHash = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        require(!done[txHash],"replayed");

        address last; uint256 count;
        for(uint i; i<sigs.length; i++){
            address s = txHash.recover(sigs[i]);
            require(s>last && _isSigner(s),"bad sig");
            last = s; count++;
        }
        require(count>=threshold,"threshold");

        done[txHash] = true;
        (bool ok, ) = address(this).call(payload);
        require(ok,"exec failed");
        emit Executed(payload, txHash);
    }

    function _isSigner(address s) internal view returns(bool){
        for(uint i; i<signers.length; i++) if(signers[i]==s) return true;
        return false;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) META‑TRANSACTION RELAY (Vulnerable vs Safe)
///─────────────────────────────────────────────────────────────────────────────
contract MetaTxVuln {
    using ECDSALib for bytes32;
    event Executed(address from, bytes payload);

    /// ❌ no nonce/expiry → replayable
    function execRelayed(
        address from,
        bytes calldata payload,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked(from, payload)).toEthSignedMessageHash();
        require(h.recover(sig)==from, "bad sig");
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(from, payload);
    }
}
contract Attack_MetaTxReplay {
    MetaTxVuln public target;
    address      public from;
    bytes        public payload;
    bytes        public sig;
    constructor(MetaTxVuln _t, address _from, bytes memory _payload, bytes memory _sig){
        target = _t; from = _from; payload = _payload; sig = _sig;
    }
    function replay() external {
        target.execRelayed(from, payload, sig);
        target.execRelayed(from, payload, sig);
    }
}

contract MetaTxSafe {
    using ECDSALib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("MetaTx(address from,bytes payload,uint256 nonce,uint256 expiry)");
    mapping(uint256=>bool) public usedNonce;

    event Executed(address from, bytes payload, uint256 nonce);

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("MtxSafe"), block.chainid, address(this)
        ));
    }

    function execRelayed(
        address from,
        bytes calldata payload,
        uint256       nonce,
        uint256       expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp<=expiry,"expired");
        require(!usedNonce[nonce],"replayed");

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, from, keccak256(payload), nonce, expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        require(digest.recover(sig)==from, "bad sig");

        usedNonce[nonce] = true;
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Executed(from, payload, nonce);
    }
}
