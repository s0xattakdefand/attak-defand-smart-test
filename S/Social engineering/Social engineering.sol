// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SocialEngineeringSuite.sol
/// @notice On‑chain analogues of four common Social‑Engineering patterns:
///   1) Phishing Approval  
///   2) Impersonation / Pretexting  
///   3) Fake Airdrop (Baiting)  
///   4) tx.origin Authentication (Tailgating)  

////////////////////////////////////////////////////////////////////////
//                             ERRORS & LIBS
////////////////////////////////////////////////////////////////////////
error ApprovalPhish__NotAllowed();
error Pretext__BadSig();
error Airdrop__BadProof();
error TxOrigin__NotOwner();

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

////////////////////////////////////////////////////////////////////////
// 1) PHISHING APPROVAL
//    Trick users into approving a malicious spender
////////////////////////////////////////////////////////////////////////
contract ERC20PhishVuln {
    mapping(address => uint256)            public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }
    function approve(address spender, uint256 amt) external {
        allowance[msg.sender][spender] = amt;
    }
    function transferFrom(address from, address to, uint256 amt) external {
        require(allowance[from][msg.sender] >= amt, "ERC20: allowance");
        allowance[from][msg.sender] -= amt;
        require(balanceOf[from] >= amt, "ERC20: balance");
        balanceOf[from] -= amt;
        balanceOf[to] += amt;
    }
}

/// Attack: steals tokens once user has been phished into `approve(attacker,…)`
contract Attack_ApprovalPhish {
    ERC20PhishVuln public token;
    constructor(ERC20PhishVuln _t) { token = _t; }
    function steal(address victim, uint256 amt) external {
        // succeeds if victim previously called approve(attacker, amt)
        token.transferFrom(victim, msg.sender, amt);
    }
}

/// Safe: only whitelisted spenders may use transferFrom
contract ApprovalGuard is ERC20PhishVuln {
    mapping(address => bool) public allowed;
    address public immutable owner;
    error NotOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function setAllowed(address spender, bool ok) external onlyOwner {
        allowed[spender] = ok;
    }

    function transferFrom(address from, address to, uint256 amt) public override {
        if (!allowed[msg.sender]) revert ApprovalPhish__NotAllowed();
        super.transferFrom(from, to, amt);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) IMPERSONATION / PRETEXTING
//    Contract trusts msg.sender identity without proof
////////////////////////////////////////////////////////////////////////
contract PretextVuln {
    address public admin;
    constructor(address _admin) { admin = _admin; }
    function sensitiveAction() external view returns (string memory) {
        require(msg.sender == admin, "PretextVuln: not admin");
        return "executed";
    }
}

/// Attack: simply calls sensitiveAction() pretending to be admin
contract Attack_Pretext {
    PretextVuln public target;
    constructor(PretextVuln _t) { target = _t; }
    function pwn() external view returns (string memory) {
        return target.sensitiveAction();
    }
}

/// Safe: binds calls to admin via EIP‑712 signed attestations
contract PretextSafe {
    using ECDSALib for bytes32;

    bytes32 public immutable DOMAIN;
    bytes32 private constant TYPEHASH =
        keccak256("Pretext(address caller,uint256 nonce,uint256 expiry)");

    address public immutable admin;
    mapping(uint256 => bool) public usedNonce;

    error BadSig();
    error Replayed();
    error Expired();

    constructor(address _admin) {
        admin = _admin;
        DOMAIN = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("PretextSafe"), keccak256("1"), block.chainid, address(this)
        ));
    }

    function sensitiveAction(
        uint256 nonce,
        uint256 expiry,
        bytes calldata sig
    ) external view returns (string memory) {
        if (block.timestamp > expiry) revert Expired();
        if (usedNonce[nonce])         revert Replayed();

        bytes32 structHash = keccak256(abi.encode(
            TYPEHASH, msg.sender, nonce, expiry
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN, structHash));
        if (digest.recover(sig) != admin) revert BadSig();

        return "executed";
    }
}

////////////////////////////////////////////////////////////////////////
// 3) FAKE AIRDROP (BAITING)
//    Bait users to call claim to receive tokens, no eligibility check
////////////////////////////////////////////////////////////////////////
contract AirdropVuln {
    mapping(address => bool) public claimed;
    ERC20PhishVuln public token;

    constructor(ERC20PhishVuln _token) { token = _token; }

    function claim() external {
        require(!claimed[msg.sender], "already claimed");
        claimed[msg.sender] = true;
        token.mint(msg.sender, 1 ether);
    }
}

/// Attack: simply calls claim() even if not intended recipient
contract Attack_Airdrop {
    AirdropVuln public airdrop;
    constructor(AirdropVuln _a) { airdrop = _a; }
    function grab() external {
        airdrop.claim();
    }
}

/// Safe: use Merkle‑proof eligibility to restrict claimants
library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 h = leaf;
        for (uint i; i < proof.length; i++) {
            bytes32 p = proof[i];
            if (h < p) h = keccak256(abi.encodePacked(h, p));
            else       h = keccak256(abi.encodePacked(p, h));
        }
        return h == root;
    }
}

contract AirdropSafe {
    bytes32 public immutable merkleRoot;
    mapping(address => bool) public claimed;
    ERC20PhishVuln public token;

    error BadProof();
    error AlreadyClaimed();

    constructor(ERC20PhishVuln _token, bytes32 _root) {
        token = _token;
        merkleRoot = _root;
    }

    function claim(bytes32[] calldata proof) external {
        if (claimed[msg.sender]) revert AlreadyClaimed();
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender));
        if (!MerkleProof.verify(proof, merkleRoot, leaf)) revert BadProof();
        claimed[msg.sender] = true;
        token.mint(msg.sender, 1 ether);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) tx.origin AUTHENTICATION (TAILGATING)
//    Misuse of tx.origin for access control
////////////////////////////////////////////////////////////////////////
contract TxOriginVuln {
    address public owner;
    constructor() { owner = msg.sender; }
    function privileged() external view returns (string memory) {
        require(tx.origin == owner, "not owner");
        return "done";
    }
}

/// Attack: contract can proxy a call so tx.origin remains EOA
contract Attack_TxOrigin {
    TxOriginVuln public target;
    constructor(TxOriginVuln _t) { target = _t; }
    function pwn() external view returns (string memory) {
        return target.privileged();
    }
}

/// Safe: use msg.sender for precise caller checks
contract TxOriginSafe {
    address public owner;
    error TxOrigin__NotOwner();
    constructor() { owner = msg.sender; }
    function privileged() external view returns (string memory) {
        if (msg.sender != owner) revert TxOrigin__NotOwner();
        return "done";
    }
}
