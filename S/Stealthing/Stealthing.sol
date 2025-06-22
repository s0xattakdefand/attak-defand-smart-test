// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StealthingSuite.sol
/// @notice Four “Stealthing” patterns illustrating common pitfalls and hardened defenses:
///   1) PUBLIC TX FRONT‑RUNNING  
///   2) NFT MINT FRONT‑RUNNING  
///   3) SECRET KEY EXPOSURE  
///   4) FUNCTION INVOCATION LEAK  

error ST__Replayed();
error ST__BadSig();
error ST__Unauthorized();
error ST__NotCommitted();
error ST__AlreadyRevealed();

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
// 1) PUBLIC TX FRONT‑RUNNING
//
//   • Vulnerable: direct withdrawal emits no commit → attacker front‑runs
//   • Attack: watch mempool and call withdraw first
//   • Defense: commit‑reveal withdrawal
////////////////////////////////////////////////////////////////////////////////
contract StealthTxVuln {
    mapping(address => uint256) public balance;

    function deposit() external payable {
        balance[msg.sender] += msg.value;
    }

    /// ❌ direct: attacker can watch mempool and steal
    function withdraw(uint256 amt) external {
        require(balance[msg.sender] >= amt, "insufficient");
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "transfer failed");
        balance[msg.sender] -= amt;
    }
}

contract Attack_StealthTx {
    StealthTxVuln public target;
    constructor(StealthTxVuln _t) { target = _t; }

    receive() external payable {
        // no reentrancy here; front‑run scenario: attacker simply calls withdraw before victim
    }

    function frontRun(uint256 amt) external {
        target.withdraw(amt);
    }
}

contract StealthTxSafe {
    using ECDSALib for bytes32;

    struct Commit { uint256 amt; bool revealed; }
    mapping(address => Commit) public commits;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Withdraw(address who,uint256 amt,uint256 nonce,uint256 expiry)");

    mapping(uint256=>bool) public usedNonce;

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("StealthTxSafe"), block.chainid, address(this)
        ));
    }

    function deposit() external payable {
        // no change
    }

    /// commit intent off‑chain via signature; on‑chain store commit
    function commitWithdraw(
        uint256 amt,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiry, "expired");
        require(!usedNonce[nonce], "replayed");
        bytes32 structHash = keccak256(abi.encode(TYPEHASH, msg.sender, amt, nonce, expiry));
        bytes32 digest     = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        address signer     = digest.recover(sig);
        require(signer == msg.sender, "bad sig");
        usedNonce[nonce]          = true;
        commits[msg.sender]       = Commit({ amt: amt, revealed: false });
    }

    /// reveal: only after commit, withdraw funds
    function revealWithdraw() external {
        Commit storage c = commits[msg.sender];
        require(c.amt > 0, "not committed");
        require(!c.revealed, "already revealed");
        c.revealed             = true;
        (bool ok, ) = msg.sender.call{value: c.amt}("");
        require(ok, "transfer failed");
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) NFT MINT FRONT‑RUNNING
//
//   • Vulnerable: public mint → attacker snipes rare token
//   • Attack: watch mempool mint tx and front‑run
//   • Defense: commit‑reveal mint with off‑chain sig
////////////////////////////////////////////////////////////////////////////////
interface IERC721 {
    function mint(uint256 tokenId) external;
}

contract StealthNFTVuln is IERC721 {
    mapping(uint256=>address) public ownerOf;
    function mint(uint256 tokenId) external override {
        require(ownerOf[tokenId]==address(0),"taken");
        ownerOf[tokenId] = msg.sender;
    }
}

contract Attack_StealthNFT {
    StealthNFTVuln public nft;
    constructor(StealthNFTVuln _n) { nft = _n; }
    function snipe(uint256 tokenId) external {
        nft.mint(tokenId);
    }
}

contract StealthNFTSafe is IERC721 {
    using ECDSALib for bytes32;

    mapping(uint256=>address) public ownerOf;
    mapping(uint256=>bool) public committed;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Mint(address who,uint256 tokenId,uint256 nonce,uint256 expiry)");

    mapping(uint256=>bool) public usedNonce;

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("StealthNFTSafe"), block.chainid, address(this)
        ));
    }

    /// commit off‑chain via signature
    function commitMint(
        uint256 tokenId,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external {
        require(ownerOf[tokenId]==address(0),"taken");
        require(block.timestamp<=expiry,"expired");
        require(!usedNonce[nonce],"replayed");
        bytes32 structHash=keccak256(abi.encode(TYPEHASH,msg.sender,tokenId,nonce,expiry));
        bytes32 digest=keccak256(abi.encodePacked("\x19\x01",DOMAIN,structHash));
        address signer=digest.recover(sig);
        require(signer==msg.sender,"bad sig");
        usedNonce[nonce]=true;
        committed[tokenId]=true;
    }

    /// reveal and mint
    function mint(uint256 tokenId) external override {
        require(committed[tokenId],"not committed");
        ownerOf[tokenId]=msg.sender;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SECRET KEY EXPOSURE
//
//   • Vulnerable: store secret key in public variable
//   • Attack: read key via public getter or extcodesize
//   • Defense: never store key on‑chain; derive per‑call via off‑chain sig
////////////////////////////////////////////////////////////////////////////////
contract KeyExposureVuln {
    bytes32 public secretKey;
    constructor(bytes32 k) { secretKey = k; }
}

contract Attack_KeyExposure {
    KeyExposureVuln public target;
    constructor(KeyExposureVuln _t) { target = _t; }
    function steal() external view returns (bytes32) {
        return target.secretKey();
    }
}

contract KeyExposureSafe {
    using ECDSALib for bytes32;
    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("GetKey(address who,uint256 nonce,uint256 expiry)");
    mapping(uint256=>bool) public usedNonce;

    constructor() {
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)"),
            keccak256("KeyExposureSafe"), block.chainid, address(this)
        ));
    }

    /// derive ephemeral session key off‑chain via manager signature
    function deriveKey(
        address manager,
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external view returns (bytes32) {
        require(block.timestamp<=expiry,"expired");
        require(!usedNonce[nonce],"replayed");
        bytes32 structHash=keccak256(abi.encode(TYPEHASH,msg.sender,nonce,expiry));
        bytes32 digest=keccak256(abi.encodePacked("\x19\x01",DOMAIN,structHash));
        address signer=digest.recover(sig);
        require(signer==manager,"bad sig");
        // not stored on‑chain
        return keccak256(abi.encodePacked(msg.sender,nonce,expiry));
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) FUNCTION INVOCATION LEAK
//
//   • Vulnerable: emits events logging sensitive payload
//   • Attack: sniff logs for function args
//   • Defense: emit only hashes or no events
////////////////////////////////////////////////////////////////////////////////
contract FunctionRevealVuln {
    event Action(address indexed who, string secret);

    function doAction(string calldata secret) external {
        // ❌ logs secret in clear
        emit Action(msg.sender, secret);
    }
}

contract Attack_FunctionReveal {
    FunctionRevealVuln public target;
    constructor(FunctionRevealVuln _t) { target = _t; }
    function trigger(string calldata s) external {
        target.doAction(s);
        // off‑chain attacker reads event and extracts s
    }
}

contract FunctionRevealSafe {
    event ActionHash(address indexed who, bytes32 secretHash);

    function doAction(string calldata secret) external {
        // ✅ emit only hash
        emit ActionHash(msg.sender, keccak256(bytes(secret)));
    }
}
