// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IERC20 {
    function transferFrom(address f, address t, uint256 a) external returns (bool);
    function transfer(address t, uint256 a) external returns (bool);
}

/* ========== POINT-TO-POINT TYPES ========== */

// 1️⃣ Static Point Tunnel
contract StaticPPP {
    address public A = 0x1111111111111111111111111111111111111111;
    address public B = 0x2222222222222222222222222222222222222222;

    function send(uint256 amount) external {
        require(msg.sender == A);
        payable(B).transfer(amount);
    }

    receive() external payable {}
}

// 2️⃣ Dynamic Forward PPP
contract TunnelPPP {
    mapping(address => address) public forward;

    function setRoute(address to) external {
        forward[msg.sender] = to;
    }

    function transfer() external payable {
        address dest = forward[msg.sender];
        require(dest != address(0), "No route");
        payable(dest).transfer(msg.value);
    }
}

// 3️⃣ Signature Tunnel PPP
contract SigPPP {
    mapping(bytes32 => bool) public used;

    function send(bytes32 hash, bytes calldata sig) external {
        require(!used[hash], "Replay");
        used[hash] = true;
        address signer = recover(hash, sig);
        payable(signer).transfer(1 ether); // refund PPP
    }

    function recover(bytes32 h, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }

    receive() external payable {}
}

// 4️⃣ Token Tunnel PPP
contract ERC20PPP {
    IERC20 public token;
    address public tunnelOut;

    constructor(IERC20 _t, address _out) {
        token = _t;
        tunnelOut = _out;
    }

    function tunnel(uint256 amt) external {
        token.transferFrom(msg.sender, tunnelOut, amt);
    }
}

// 5️⃣ ZKProof PPP (mocked)
contract ZKPPP {
    bytes32 public zkProof;

    function enter(bytes32 proof) external {
        require(proof == zkProof, "Bad ZK");
    }

    function setProof(bytes32 p) external {
        zkProof = p;
    }
}

/* ========== ATTACK VECTORS ========== */

// Route injection
contract SpoofTunnel {
    function hijack(TunnelPPP p, address me) external {
        p.setRoute(me);
    }
}

// Signature replay
contract ReplaySig {
    function exploit(SigPPP t, bytes32 h, bytes calldata sig) external {
        t.send(h, sig); // reuse old sig
    }
}

/* ========== DEFENSE MODULES ========== */

// 🛡️ Route Hash Lock
contract HashRouter {
    bytes32 public locked;

    function bind(address a, address b) external {
        locked = keccak256(abi.encode(a, b));
    }

    function verify(address a, address b) external view returns (bool) {
        return locked == keccak256(abi.encode(a, b));
    }
}

// 🛡️ Sig + Nonce Lock
contract PPPNonce {
    mapping(address => uint256) public used;

    function guard(address user, uint256 nonce) external {
        require(nonce > used[user], "Used nonce");
        used[user] = nonce;
    }
}

// 🛡️ Relay Registry
contract RelayWhitelist {
    mapping(address => bool) public trusted;

    function approve(address r, bool ok) external {
        trusted[r] = ok;
    }

    modifier onlyRelay() {
        require(trusted[msg.sender], "Not relay");
        _;
    }

    function relayOnlyCall() external onlyRelay returns (bool) {
        return true;
    }
}

// 🛡️ Tunnel In/Out Match
contract EntropyMatch {
    mapping(address => bytes32) public inbound;

    function mark(bytes32 id) external {
        inbound[msg.sender] = id;
    }

    function exit(bytes32 id) external view returns (bool) {
        return inbound[msg.sender] == id;
    }
}
