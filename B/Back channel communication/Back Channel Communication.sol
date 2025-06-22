// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title BackChannelCommunicationSuite.sol
/// @notice On-chain analogues of “Back Channel Communication” patterns:
///   Types: Synchronous, Asynchronous, Covert, OutOfBand  
///   AttackTypes: Eavesdropping, Manipulation, Denial, Replay  
///   DefenseTypes: Encryption, Authentication, RateLimit, Monitoring  

enum BackChannelType             { Synchronous, Asynchronous, Covert, OutOfBand }
enum BackChannelAttackType       { Eavesdropping, Manipulation, Denial, Replay }
enum BackChannelDefenseType      { Encryption, Authentication, RateLimit, Monitoring }

error BC__Unauthorized();
error BC__TooManyRequests();
error BC__InvalidSignature();
error BC__Tampered();
error BC__NotAllowed();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE CHANNEL (no confidentiality/integrity)
//    • anyone can send or listen on the back-channel → Eavesdropping, Manipulation
////////////////////////////////////////////////////////////////////////////////
contract BackChannelVuln {
    event MessageSent(
        address indexed from,
        address indexed to,
        BackChannelType   ctype,
        bytes             payload,
        BackChannelAttackType attack
    );

    function sendMessage(address to, BackChannelType ctype, bytes calldata payload) external {
        // ❌ no confidentiality or integrity checks
        emit MessageSent(msg.sender, to, ctype, payload, BackChannelAttackType.Manipulation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • demonstrates eavesdropping (reading events) and replay
////////////////////////////////////////////////////////////////////////////////
contract Attack_BackChannel {
    BackChannelVuln public target;
    bytes public lastPayload;

    constructor(BackChannelVuln _t) { target = _t; }

    function capture(bytes calldata payload) external {
        lastPayload = payload;
    }

    function replay(address to, BackChannelType ctype) external {
        target.sendMessage(to, ctype, lastPayload);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE CHANNEL WITH ENCRYPTION
//    • Defense: Encryption – encrypt payload off-chain, deliver ciphertext
////////////////////////////////////////////////////////////////////////////////
contract BackChannelSafeEncryption {
    event MessageSent(
        address indexed from,
        address indexed to,
        BackChannelType       ctype,
        bytes                 ciphertext,
        BackChannelDefenseType defense
    );

    function sendMessage(address to, BackChannelType ctype, bytes calldata ciphertext) external {
        // assume off-chain encryption ensures confidentiality/integrity
        emit MessageSent(msg.sender, to, ctype, ciphertext, BackChannelDefenseType.Encryption);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE CHANNEL WITH RATE-LIMITING
//    • Defense: RateLimit – cap messages per block per sender
////////////////////////////////////////////////////////////////////////////////
contract BackChannelSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public msgsInBlock;
    uint256 public constant MAX_MSGS_PER_BLOCK = 5;

    event MessageSent(
        address indexed from,
        address indexed to,
        BackChannelType       ctype,
        bytes                 payload,
        BackChannelDefenseType defense
    );

    error BC__TooManyRequests();

    function sendMessage(address to, BackChannelType ctype, bytes calldata payload) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]  = block.number;
            msgsInBlock[msg.sender] = 0;
        }
        msgsInBlock[msg.sender]++;
        if (msgsInBlock[msg.sender] > MAX_MSGS_PER_BLOCK) revert BC__TooManyRequests();

        emit MessageSent(msg.sender, to, ctype, payload, BackChannelDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED CHANNEL WITH AUTHENTICATION & MONITORING
//    • Defense: Authentication – require signed payload  
//               Monitoring – log and alert on anomalies
////////////////////////////////////////////////////////////////////////////////
contract BackChannelSafeAdvanced {
    address public signer;
    mapping(address => uint256) public lastSentBlock;
    event MessageSent(
        address indexed from,
        address indexed to,
        BackChannelType       ctype,
        bytes                 payload,
        BackChannelDefenseType defense
    );
    event AnomalyDetected(
        address indexed who,
        string               reason,
        BackChannelDefenseType defense
    );

    error BC__InvalidSignature();
    error BC__TooManyRequests();

    constructor(address _signer) {
        signer = _signer;
    }

    function sendMessage(
        address to,
        BackChannelType ctype,
        bytes calldata payload,
        bytes calldata sig
    ) external {
        // rate-limit once per block
        if (lastSentBlock[msg.sender] == block.number) {
            revert BC__TooManyRequests();
        }
        lastSentBlock[msg.sender] = block.number;

        // authentication: verify off-chain signature over payload
        bytes32 msgHash = keccak256(abi.encodePacked(msg.sender, to, ctype, payload));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8, bytes32, bytes32));
        if (ecrecover(ethMsg, v, r, s) != signer) {
            emit AnomalyDetected(msg.sender, "invalid signature", BackChannelDefenseType.Monitoring);
            revert BC__InvalidSignature();
        }

        // deliver message
        emit MessageSent(msg.sender, to, ctype, payload, BackChannelDefenseType.Authentication);
    }
}
