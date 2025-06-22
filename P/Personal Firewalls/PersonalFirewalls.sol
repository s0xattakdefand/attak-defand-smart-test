// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ================== FIREWALL TYPES ================== */

// 1️⃣ Address Whitelist Firewall
contract WhitelistFirewall {
    mapping(address => bool) public approved;

    modifier onlyApproved() {
        require(approved[msg.sender], "Firewall: blocked");
        _;
    }

    function allow(address user, bool yes) external {
        approved[user] = yes;
    }

    function safeFunction() external onlyApproved returns (string memory) {
        return "Approved call!";
    }
}

// 2️⃣ Selector Firewall
contract SelectorFirewall {
    mapping(bytes4 => bool) public allowedSelectors;

    fallback() external {
        require(allowedSelectors[msg.sig], "Selector blocked");
    }

    function setSelector(bytes4 s, bool allow) external {
        allowedSelectors[s] = allow;
    }
}

// 3️⃣ Role Zone Firewall
contract RoleZoneFirewall {
    mapping(address => uint8) public zone;

    modifier onlyZone(uint8 z) {
        require(zone[msg.sender] == z, "Zone mismatch");
        _;
    }

    function assign(address user, uint8 z) external {
        zone[user] = z;
    }

    function zoneRestrictedAction() external onlyZone(1) returns (string memory) {
        return "Zone 1 Access";
    }
}

// 4️⃣ Signature Firewall
contract SigFirewall {
    mapping(address => uint256) public usedNonce;

    function check(bytes32 hash, bytes calldata sig, uint256 nonce) external {
        require(nonce > usedNonce[msg.sender], "Used");
        usedNonce[msg.sender] = nonce;
        require(recover(hash, sig) == msg.sender, "Sig mismatch");
    }

    function recover(bytes32 h, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }
}

// 5️⃣ Rate Limit Firewall
contract RateLimitFirewall {
    mapping(address => uint256) public last;

    modifier cooldown() {
        require(block.timestamp > last[msg.sender] + 10, "Rate limit");
        last[msg.sender] = block.timestamp;
        _;
    }

    function rateSafeAction() external cooldown returns (string memory) {
        return "Allowed by cooldown";
    }
}

/* ================== FIREWALL ATTACKS ================== */

// 1️⃣ Spoofed Caller Injection
contract ForwardSpoof {
    function spoof(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data); // attacker isn't the true origin
        require(ok);
    }
}

// 2️⃣ Signature Drift Replay
contract ReplaySigDrift {
    function replay(address target, bytes32 hash, bytes calldata sig, uint256 nonce) external {
        target.call(abi.encodeWithSignature("check(bytes32,bytes,uint256)", hash, sig, nonce));
    }
}

// 3️⃣ Relay Proxy Bypass
contract RelayBypass {
    fallback() external {
        // just proxy all payloads
        address t = address(0xDead); // change target as needed
        (bool ok, ) = t.call(msg.data);
        require(ok);
    }
}

// 4️⃣ Selector Overload
contract SelectorInjector {
    function overload(address t, bytes calldata payload) external {
        t.call(payload);
    }
}

// 5️⃣ Gas Reentry Bypass
contract GasBypass {
    address public target;

    receive() external payable {
        if (gasleft() > 10000) {
            target.call(abi.encodeWithSignature("rateSafeAction()"));
        }
    }

    function trigger(address t) external payable {
        target = t;
        RateLimitFirewall(t).rateSafeAction();
    }
}
