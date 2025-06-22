// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StandardACLsSuite.sol
/// @notice Four “Standard ACLs” patterns with common pitfalls and hardened defenses:
///   1) No‑Default‑Deny  
///   2) Source‑Spoofing  
///   3) Missing Audit Logs  
///   4) Unbounded Rule Table  

error ACL__NotAllowed();
error ACL__PacketSpoof();
error ACL__TooManyEntries();

/// Simple “packet” struct for spoofing demo
struct Packet {
    address src;
    address dst;
    bytes   data;
}

////////////////////////////////////////////////////////////////////////
// 1) NO‑DEFAULT‑DENY
//    • Vulnerable: missing deny check → default allow all
//    • Attack: anyone can send arbitrary calls
//    • Defense: enforce explicit allow list (default deny)
////////////////////////////////////////////////////////////////////////
contract NoDefaultDenyVuln {
    function send(address dst, bytes calldata data) external {
        // ❌ no ACL check – default allow
        (bool ok, ) = dst.call(data);
        require(ok, "call failed");
    }
}

contract NoDefaultDenySafe {
    mapping(address => bool) public allowed;

    /// only authorized callers may send
    function allow(address who) external {
        allowed[who] = true;
    }

    function send(address dst, bytes calldata data) external {
        if (!allowed[msg.sender]) revert ACL__NotAllowed();
        (bool ok, ) = dst.call(data);
        require(ok, "call failed");
    }
}

////////////////////////////////////////////////////////////////////////
// 2) SOURCE‑SPOOFING
//    • Vulnerable: trusts user‑supplied src field → spoofable
//    • Attack: attacker sets Packet.src = victim to bypass ACL
//    • Defense: ignore Packet.src, use msg.sender as true source
////////////////////////////////////////////////////////////////////////
contract SpoofACLVuln {
    mapping(address => bool) public allowed;

    function allow(address who) external {
        allowed[who] = true;
    }

    function route(Packet calldata p) external {
        // ❌ trusts p.src, not msg.sender
        require(allowed[p.src], "not allowed");
        (bool ok, ) = p.dst.call(p.data);
        require(ok, "call failed");
    }
}

contract SpoofACLSafe {
    mapping(address => bool) public allowed;

    function allow(address who) external {
        allowed[who] = true;
    }

    function route(Packet calldata p) external {
        // ✅ enforce msg.sender == true source
        if (!allowed[msg.sender])          revert ACL__NotAllowed();
        if (p.src != msg.sender)           revert ACL__PacketSpoof();
        (bool ok, ) = p.dst.call(p.data);
        require(ok, "call failed");
    }
}

////////////////////////////////////////////////////////////////////////
// 3) MISSING AUDIT LOGS
//    • Vulnerable: no logging of allow or deny events
//    • Attack: unauthorized access attempts go unnoticed
//    • Defense: emit structured events on every decision
////////////////////////////////////////////////////////////////////////
contract LogACLVuln {
    mapping(address => bool) public allowed;

    function allow(address who) external {
        allowed[who] = true;
    }

    function send(address dst, bytes calldata data) external {
        require(allowed[msg.sender], "not allowed");
        (bool ok, ) = dst.call(data);
        require(ok, "call failed");
        // ❌ no audit log
    }
}

contract LogACLSafe {
    mapping(address => bool) public allowed;
    event AccessAttempt(address indexed who, address indexed dst, bool permitted);

    function allow(address who) external {
        allowed[who] = true;
    }

    function send(address dst, bytes calldata data) external {
        bool permitted = allowed[msg.sender];
        emit AccessAttempt(msg.sender, dst, permitted);
        if (!permitted) revert ACL__NotAllowed();
        (bool ok, ) = dst.call(data);
        require(ok, "call failed");
    }
}

////////////////////////////////////////////////////////////////////////
// 4) UNBOUNDED RULE TABLE
//    • Vulnerable: no limit on ACL entries → DoS via large storage use
//    • Attack: spam allow() to exhaust gas or storage
//    • Defense: cap total entries and prevent duplicates
////////////////////////////////////////////////////////////////////////
contract CapACLVuln {
    mapping(address => bool) public allowed;

    function allow(address who) external {
        allowed[who] = true;  // ❌ no cap
    }
}

contract CapACLSafe {
    mapping(address => bool) public allowed;
    address[] public entries;
    uint256 public constant MAX_ENTRIES = 128;

    error ACL__TooManyEntries();

    function allow(address who) external {
        if (!allowed[who]) {
            if (entries.length >= MAX_ENTRIES) revert ACL__TooManyEntries();
            allowed[who] = true;
            entries.push(who);
        }
    }
}
