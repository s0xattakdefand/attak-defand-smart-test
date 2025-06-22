// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SpamSuite.sol
/// @notice Four “Spam” patterns illustrating common pitfalls in on‑chain messaging
///         and hardened defenses.

error Spam__NotAllowed();
error Spam__TooMany();
error Spam__BadContent();

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED MESSAGING
//
//   • Vulnerable: anyone can send messages to any recipient
//   • Attack: spam any address with unsolicited messages
//   • Defense: restrict senders via an allowlist
////////////////////////////////////////////////////////////////////////
contract SpamVuln1 {
    event Message(address indexed from, address indexed to, string content);

    /// ❌ no access control
    function sendMessage(address to, string calldata content) external {
        emit Message(msg.sender, to, content);
    }
}

contract Attack_Spam1 {
    SpamVuln1 public target;
    constructor(SpamVuln1 _t) { target = _t; }

    /// attacker floods a victim with messages
    function flood(address victim, string calldata msgContent, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            target.sendMessage(victim, msgContent);
        }
    }
}

contract SpamSafe1 {
    event Message(address indexed from, address indexed to, string content);
    mapping(address => bool) public allowed;

    address public owner;
    error Spam__NotAllowed();

    constructor() { owner = msg.sender; }

    /// only owner may whitelist senders
    function setAllowed(address who, bool ok) external {
        require(msg.sender == owner, "SpamSafe1: only owner");
        allowed[who] = ok;
    }

    /// ✅ only allowed senders may send
    function sendMessage(address to, string calldata content) external {
        if (!allowed[msg.sender]) revert Spam__NotAllowed();
        emit Message(msg.sender, to, content);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) BULK MESSAGING FLOOD (DoS)
//
//   • Vulnerable: unlimited recipients per bulk send
//   • Attack: sendBulk with huge array to exhaust gas
//   • Defense: cap bulk size
////////////////////////////////////////////////////////////////////////
contract BulkSpamVuln {
    event BulkMessage(address indexed from, address indexed to, string content);

    /// ❌ no limit on number of recipients
    function sendBulk(address[] calldata recipients, string calldata content) external {
        for (uint256 i = 0; i < recipients.length; i++) {
            emit BulkMessage(msg.sender, recipients[i], content);
        }
    }
}

contract Attack_BulkSpam {
    BulkSpamVuln public target;
    constructor(BulkSpamVuln _t) { target = _t; }

    function flood(address[] calldata recips, string calldata c) external {
        target.sendBulk(recips, c);
    }
}

contract BulkSpamSafe {
    event BulkMessage(address indexed from, address indexed to, string content);
    uint256 public constant MAX_BULK = 50;
    error Spam__TooMany();

    /// ✅ enforce cap on bulk size
    function sendBulk(address[] calldata recipients, string calldata content) external {
        if (recipients.length > MAX_BULK) revert Spam__TooMany();
        for (uint256 i = 0; i < recipients.length; i++) {
            emit BulkMessage(msg.sender, recipients[i], content);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) LOG INJECTION VIA MESSAGES
//
//   • Vulnerable: logs raw content, allowing injection of control text
//   • Attack: include semicolons or misleading sequences
//   • Defense: emit only hash of content
////////////////////////////////////////////////////////////////////////
contract SpamLogVuln {
    event Logged(address indexed from, string content);

    function logMessage(string calldata content) external {
        emit Logged(msg.sender, content);
    }
}

contract Attack_SpamLog {
    SpamLogVuln public target;
    constructor(SpamLogVuln _t) { target = _t; }

    function inject(string calldata payload) external {
        // attacker injects control characters or misleading text
        target.logMessage(payload);
    }
}

contract SpamLogSafe {
    event Logged(address indexed from, bytes32 contentHash);
    error Spam__BadContent();

    function logMessage(string calldata content) external {
        // simple length check to avoid extremely large payload
        if (bytes(content).length > 512) revert Spam__BadContent();
        emit Logged(msg.sender, keccak256(bytes(content)));
    }
}

////////////////////////////////////////////////////////////////////////
// 4) CONTENT FILTERING
//
//   • Vulnerable: no check for prohibited terms
//   • Attack: send messages containing banned words
//   • Defense: reject messages containing forbidden substrings
////////////////////////////////////////////////////////////////////////
contract SpamFilterVuln {
    event Message(address indexed from, address indexed to, string content);

    function sendMessage(address to, string calldata content) external {
        emit Message(msg.sender, to, content);
    }
}

contract Attack_SpamFilter {
    SpamFilterVuln public target;
    constructor(SpamFilterVuln _t) { target = _t; }

    function sendBad(address to) external {
        // includes the word “spam” to bypass naive filters
        target.sendMessage(to, "This is spam content; click here!");
    }
}

contract SpamFilterSafe {
    event Message(address indexed from, address indexed to, string content);
    error Spam__BadContent();

    /// ✅ reject messages containing “spam” (case‑sensitive)
    function sendMessage(address to, string calldata content) external {
        bytes memory b = bytes(content);
        bytes memory ban = bytes("spam");
        for (uint256 i = 0; i + ban.length <= b.length; i++) {
            bool match_ = true;
            for (uint256 j = 0; j < ban.length; j++) {
                if (b[i + j] != ban[j]) { match_ = false; break; }
            }
            if (match_) revert Spam__BadContent();
        }
        emit Message(msg.sender, to, content);
    }
}
