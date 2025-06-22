// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WhalingSuite.sol
/// @notice On‐chain analogues of “Whaling” (high‐value phishing) patterns:
///   Types: Executive, Finance, HR, IT  
///   AttackTypes: PhishingEmail, SpearPhishing, CEOImpersonation, InvoiceFraud  
///   DefenseTypes: AwarenessTraining, EmailFiltering, VerificationCall, RateLimit

enum WhalingType            { Executive, Finance, HR, IT }
enum WhalingAttackType      { PhishingEmail, SpearPhishing, CEOImpersonation, InvoiceFraud }
enum WhalingDefenseType     { AwarenessTraining, EmailFiltering, VerificationCall, RateLimit }

error WHA__NotTrained();
error WHA__Blocked();
error WHA__VerificationFailed();
error WHA__TooManyRequests();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE PHISHING TARGET
//
//    • ❌ no checks: any email is delivered → PhishingEmail
////////////////////////////////////////////////////////////////////////////////
contract WhalingVuln {
    event EmailReceived(
        address indexed to,
        string            subject,
        string            body,
        WhalingType       wtype,
        WhalingAttackType attack
    );

    function sendEmail(
        address to,
        string calldata subject,
        string calldata body,
        WhalingType wtype
    ) external {
        emit EmailReceived(to, subject, body, wtype, WhalingAttackType.PhishingEmail);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates phishing, spear‐phishing, CEO fraud, invoice scams
////////////////////////////////////////////////////////////////////////////////
contract Attack_Whaling {
    WhalingVuln public target;

    constructor(WhalingVuln _t) {
        target = _t;
    }

    function phishEmail(address to, string calldata subject, string calldata body) external {
        target.sendEmail(to, subject, body, WhalingType.Executive);
    }

    function spearPhish(address to, string calldata subject, string calldata body) external {
        target.sendEmail(to, subject, body, WhalingType.Finance);
    }

    function impersonateCEO(address to, string calldata subject, string calldata body) external {
        target.sendEmail(to, subject, body, WhalingType.Executive);
    }

    function invoiceFraud(address to, string calldata subject, string calldata body) external {
        target.sendEmail(to, subject, body, WhalingType.Finance);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH AWARENESS TRAINING
//
//    • ✅ Defense: AwarenessTraining – only trained users get emails
////////////////////////////////////////////////////////////////////////////////
contract WhalingSafeTraining {
    mapping(address => bool) public trained;
    event EmailReceived(
        address indexed to,
        string            subject,
        string            body,
        WhalingDefenseType defense
    );

    error WHA__NotTrained();

    function train(address user, bool ok) external {
        // stub: admin can grant training
        trained[user] = ok;
    }

    function sendEmail(
        address to,
        string calldata subject,
        string calldata body,
        WhalingType /*wtype*/
    ) external {
        if (!trained[to]) revert WHA__NotTrained();
        emit EmailReceived(to, subject, body, WhalingDefenseType.AwarenessTraining);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH EMAIL FILTERING
//
//    • ✅ Defense: EmailFiltering – block suspicious keywords
////////////////////////////////////////////////////////////////////////////////
contract WhalingSafeFilter {
    mapping(string => bool) public blockedKeyword;
    event EmailReceived(
        address indexed to,
        string            subject,
        string            body,
        WhalingDefenseType defense
    );
    error WHA__Blocked();

    function setBlockedKeyword(string calldata kw, bool ok) external {
        // stub: admin
        blockedKeyword[kw] = ok;
    }

    function _containsBlocked(string memory text) internal view returns (bool) {
        bytes memory t = bytes(text);
        for (uint i; i +  bytes("http").length <= t.length; i++) {
            bool match;
            for (uint j; j < bytes("http").length; j++) {
                if (t[i + j] != bytes("http")[j]) { match = false; break; }
                match = true;
            }
            if (match && blockedKeyword["http"]) return true;
        }
        return false;
    }

    function sendEmail(
        address to,
        string calldata subject,
        string calldata body,
        WhalingType /*wtype*/
    ) external {
        if (_containsBlocked(subject) || _containsBlocked(body)) revert WHA__Blocked();
        emit EmailReceived(to, subject, body, WhalingDefenseType.EmailFiltering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH VERIFICATION CALL & RATE LIMIT
//
//    • ✅ Defense: VerificationCall + RateLimit – require code and cap emails
////////////////////////////////////////////////////////////////////////////////
contract WhalingSafeAdvanced {
    mapping(address => bytes32) public verificationCode;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public emailsInBlock;
    uint256 public constant MAX_EMAILS = 5;

    event EmailReceived(
        address indexed to,
        string            subject,
        string            body,
        WhalingDefenseType defense
    );
    error WHA__VerificationFailed();
    error WHA__TooManyRequests();

    function setVerificationCode(address user, bytes32 code) external {
        // stub: admin sets code
        verificationCode[user] = code;
    }

    function sendEmail(
        address to,
        string calldata subject,
        string calldata body,
        WhalingType /*wtype*/,
        bytes32 code
    ) external {
        // rate-limit per recipient
        if (block.number != lastBlock[to]) {
            lastBlock[to]    = block.number;
            emailsInBlock[to] = 0;
        }
        emailsInBlock[to]++;
        if (emailsInBlock[to] > MAX_EMAILS) revert WHA__TooManyRequests();

        // require correct code
        if (verificationCode[to] != code) revert WHA__VerificationFailed();
        emit EmailReceived(to, subject, body, WhalingDefenseType.VerificationCall);
    }
}
