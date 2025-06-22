// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TransmissionControlProtocolSuite.sol
/// @notice On‑chain analogues of “Transmission Control Protocol” (TCP) patterns:
///   Types: Handshake, Termination, FlowControl, CongestionControl  
///   AttackTypes: SequencePrediction, RSTInjection, WindowHijack, SYNFlood  
///   DefenseTypes: ISNRandomization, SYNCookie, RSTValidation, CWNDCheck  

enum TransmissionControlProtocolType  { Handshake, Termination, FlowControl, CongestionControl }
enum TransmissionControlProtocolAttackType { SequencePrediction, RSTInjection, WindowHijack, SYNFlood }
enum TransmissionControlProtocolDefenseType { ISNRandomization, SYNCookie, RSTValidation, CWNDCheck }

error TCP__InvalidSeq();
error TCP__NotAuthorized();
error TCP__CookieInvalid();
error TCP__WindowViolated();

///─────────────────────────────────────────────────────────────────────────────
/// 1) VULNERABLE HANDSHAKE & SEQUENCE PREDICTION
///
///   • Uses a fixed initial sequence number (1000) → attackers predict it
///   • AttackType: SequencePrediction
///─────────────────────────────────────────────────────────────────────────────
contract TCPVulnHandshake {
    struct Conn { address peer; uint32 seq; bool established; }
    mapping(address => Conn) public conns;

    /// initiate handshake with fixed ISN
    function initiate(address peer) external {
        // ❌ fixed ISN = 1000
        conns[msg.sender] = Conn(peer, 1000, false);
    }

    /// complete handshake with ACK
    function ack(address initiator, uint32 ackSeq) external {
        Conn storage c = conns[initiator];
        require(c.peer == msg.sender, "no such conn");
        // ❌ no validation of seq
        c.established = true;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) ATTACK STUB: predicts the sequence and ACKs out‑of‑turn
///─────────────────────────────────────────────────────────────────────────────
contract Attack_TCPSequencePrediction {
    TCPVulnHandshake public target;
    constructor(TCPVulnHandshake _t) { target = _t; }

    /// attacker initiates and immediately ACKs with predicted seq
    function exploit(address victim) external {
        target.initiate(victim);
        // predict fixed ISN=1000, so ACK with 1001
        target.ack(victim, 1001);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) SAFE HANDSHAKE WITH ISN RANDOMIZATION
///
///   • Defense: randomize initial sequence via keccak256 and blockhash
///   • AttackType defended: SequencePrediction
///─────────────────────────────────────────────────────────────────────────────
contract TCPISNRandomSafe {
    struct Conn { address peer; uint32 seq; bool established; }
    mapping(address => Conn) public conns;

    event HandshakeSent(address indexed from, address indexed to, uint32 isn, TransmissionControlProtocolDefenseType defense);

    /// random initial sequence based on blockhash and timestamp
    function initiate(address peer) external {
        // ✅ ISN randomization
        uint32 isn = uint32(uint256(keccak256(abi.encodePacked(msg.sender, peer, blockhash(block.number-1), block.timestamp))));
        conns[msg.sender] = Conn(peer, isn, false);
        emit HandshakeSent(msg.sender, peer, isn, TransmissionControlProtocolDefenseType.ISNRandomization);
    }

    function ack(address initiator, uint32 ackSeq) external {
        Conn storage c = conns[initiator];
        require(c.peer == msg.sender, "no such conn");
        // ❌ still no further seq checks here
        c.established = true;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SAFE SYN FLOOD PROTECTION VIA COOKIE & RST VALIDATION
///
///   • Defense: SYN cookie for handshake + validate RST sequence  
///   • AttackTypes defended: SYNFlood, RSTInjection
///─────────────────────────────────────────────────────────────────────────────
contract TCPSynCookieSafe {
    struct Cookie { address client; uint32 seq; }
    mapping(bytes32 => Cookie) public cookies;
    mapping(address => bool) public established;
    mapping(address => uint32) public lastSeenSeq;

    event SynCookieIssued(address indexed client, bytes32 cookie, TransmissionControlProtocolDefenseType defense);
    event ConnectionEstablished(address indexed client);

    /// issue SYN cookie instead of storing half‑open state
    function syn(address client) external returns (bytes32 cookie) {
        // ✅ random cookie tied to client & timestamp
        cookie = keccak256(abi.encodePacked(client, block.timestamp, blockhash(block.number-1)));
        cookies[cookie] = Cookie(client, uint32(block.timestamp));
        emit SynCookieIssued(client, cookie, TransmissionControlProtocolDefenseType.SYNCookie);
    }

    /// client presents cookie and seq to complete handshake
    function ack(address client, bytes32 cookie, uint32 seq) external {
        Cookie memory c = cookies[cookie];
        require(c.client == client, "bad cookie");
        // ✅ validate RST/ACK seq is within window
        require(seq >= c.seq && seq <= c.seq + 1000, "seq out of window");
        established[client] = true;
        lastSeenSeq[client] = seq;
        delete cookies[cookie];
        emit ConnectionEstablished(client);
    }

    /// handle RST: only allow if seen in established conn
    function rst(address client, uint32 rstSeq) external {
        require(established[client], "no conn");
        // ✅ validate RST Seq matches last seen
        if (rstSeq != lastSeenSeq[client]) revert TCP__RSTValidation();
        established[client] = false; // tear down
    }
}

