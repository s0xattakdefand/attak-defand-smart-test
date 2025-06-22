// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ==================== PAYLOAD TYPES ==================== */

// 1️⃣ Calldata Payload
contract CalldataPayload {
    event Payload(bytes data, address sender);

    function submit(bytes calldata data) external {
        emit Payload(data, msg.sender);
    }
}

// 2️⃣ Delegatecall Payload
contract DelegateExecutor {
    address public logic;

    function setLogic(address _logic) external {
        logic = _logic;
    }

    function execute(bytes calldata payload) external {
        (bool ok, ) = logic.delegatecall(payload);
        require(ok, "Delegate failed");
    }
}

// 3️⃣ MetaTx Payload
contract MetaTxForwarder {
    mapping(address => uint256) public nonce;

    function forward(bytes calldata payload, bytes calldata sig, uint256 n) external {
        require(n == nonce[msg.sender], "Invalid nonce");
        bytes32 hash = keccak256(payload);
        require(recover(hash, sig) == msg.sender, "Invalid sig");
        nonce[msg.sender]++;
        (bool ok, ) = address(this).call(payload);
        require(ok);
    }

    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

// 4️⃣ Encoded Packet Payload
contract EncodedRouter {
    mapping(bytes4 => address) public targets;

    function route(bytes calldata data) external {
        bytes4 sel = bytes4(data);
        address target = targets[sel];
        require(target != address(0), "No route");
        (bool ok, ) = target.call(data);
        require(ok);
    }
}

// 5️⃣ zkProof Payload
contract zkPayloadValidator {
    bytes32 public validProof;

    function submit(bytes calldata zkProof) external view returns (bool) {
        return keccak256(zkProof) == validProof;
    }
}

/* ==================== ATTACKS ==================== */

// 1️⃣ Selector Injection
contract SelectorInjector {
    function inject(address t, bytes calldata data) external {
        (bool ok, ) = t.call(data);
        require(ok);
    }
}

// 2️⃣ Delegate Drift
contract DriftDelegate {
    function drift(address delegateTarget, bytes calldata evilPayload) external {
        delegateTarget.delegatecall(evilPayload);
    }
}

// 3️⃣ MetaTx Replay
contract MetaTxReplayer {
    function replay(address fwd, bytes calldata p, bytes calldata sig, uint256 n) external {
        fwd.call(abi.encodeWithSelector(
            bytes4(keccak256("forward(bytes,bytes,uint256)")), p, sig, n
        ));
    }
}

// 4️⃣ zk Drift Injection
contract DriftZKPayload {
    function push(bytes calldata invalidZK, address target) external {
        target.call(abi.encodeWithSignature("submit(bytes)", invalidZK));
    }
}

// 5️⃣ Calldata Overrun
contract OverflowExploit {
    function overrun(address victim, bytes calldata payload) external {
        victim.call(payload);
    }
}

/* ==================== DEFENSES ==================== */

// 🛡️ 1 Calldata Length Verifier
contract CalldataLengthGuard {
    function check(bytes calldata input) external pure returns (bool) {
        return input.length >= 4;
    }
}

// 🛡️ 2 MetaTx Nonce Lock
contract MetaNonceDefense {
    mapping(address => uint256) public last;

    function validate(uint256 n) external {
        require(n > last[msg.sender], "Replay attempt");
        last[msg.sender] = n;
    }
}

// 🛡️ 3 Selector Whitelist
contract SelectorGuard {
    mapping(bytes4 => bool) public allowed;

    function set(bytes4 s, bool y) external {
        allowed[s] = y;
    }

    fallback() external {
        require(allowed[msg.sig], "Selector blocked");
    }
}

// 🛡️ 4 Delegate Registry
contract DelegateValidator {
    mapping(address => bool) public isSafe;

    function allow(address t, bool y) external {
        isSafe[t] = y;
    }

    function safeDelegate(address t, bytes calldata data) external {
        require(isSafe[t], "Not trusted");
        (bool ok, ) = t.delegatecall(data);
        require(ok);
    }
}

// 🛡️ 5 zkPayload Hash Lock
contract zkPayloadHash {
    bytes32 public accepted;

    function set(bytes32 h) external {
        accepted = h;
    }

    function check(bytes calldata d) external view returns (bool) {
        return keccak256(d) == accepted;
    }
}
