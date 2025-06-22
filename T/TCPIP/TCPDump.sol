// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TCPIPSuite.sol
/// @notice On‑chain analogues of common “TCP/IP” patterns and defenses.

enum IPProtocol           { TCP, UDP }
enum TCPFlag              { SYN, ACK, FIN, RST }
enum TCPIPAttackType      { IPSpoof, TCPSYNFlood, FragOverlap, TTLManipulation }
enum TCPIPDefenseType     { RPF, SYNCookie, StrictReassembly, TTLCheck }

error TCPIP__SpoofDetected();
error TCPIP__TooManyHalfOpens();
error TCPIP__OverlapDetected();
error TCPIP__TTLTooLow();

////////////////////////////////////////////////////////////////////////
// 1) IP SPOOFING
//
//  • Vulnerable: trusts user‑supplied src address
//  • Attack: spoof Packet.src to another address
//  • Defense: reverse‑path filter (RPF): require msg.sender == src
////////////////////////////////////////////////////////////////////////
contract IPSpoofVuln {
    struct Packet { address src; address dst; IPProtocol proto; bytes data; }
    event Received(address src, address dst, IPProtocol proto, bytes data);

    /// ❌ trusts p.src blindly
    function receive(Packet calldata p) external {
        emit Received(p.src, p.dst, p.proto, p.data);
    }
}

contract Attack_IPSpoof {
    IPSpoofVuln public target;
    constructor(IPSpoofVuln _t) { target = _t; }

    /// spoofing src as victimAddr
    function spoof(address victimAddr, address dst) external {
        IPSpoofVuln.Packet memory p = IPSpoofVuln.Packet({
            src: victimAddr,
            dst: dst,
            proto: IPProtocol.TCP,
            data: ""
        });
        target.receive(p);
    }
}

contract IPSpoofSafe {
    event Received(address src, address dst, IPProtocol proto, bytes data);
    error TCPIP__SpoofDetected();

    /// ✅ require msg.sender == p.src
    function receive(address src, address dst, IPProtocol proto, bytes calldata data) external {
        if (msg.sender != src) revert TCPIP__SpoofDetected();
        emit Received(src, dst, proto, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) TCP SYN FLOOD (Half‑Open Scan)
// 
//  • Vulnerable: unlimited half‑opens stored
//  • Attack: SYN flood (lots of half‑opens)
//  • Defense: SYN cookies + rate‑limit
////////////////////////////////////////////////////////////////////////
contract TCPSynFloodVuln {
    mapping(address => uint) public halfOpenCount;
    event SynReceived(address indexed from, address indexed to, uint16 port);

    /// ❌ no limit on half‑opens
    function syn(address to, uint16 port) external {
        halfOpenCount[msg.sender]++;
        emit SynReceived(msg.sender, to, port);
    }
}

contract Attack_TCPSynFlood {
    TCPSynFloodVuln public target;
    constructor(TCPSynFloodVuln _t) { target = _t; }

    function flood(address to, uint16 port, uint n) external {
        for (uint i = 0; i < n; i++) {
            target.syn(to, port);
        }
    }
}

contract TCPSynFloodSafe {
    address public owner;
    mapping(address => uint) public halfOpenCount;
    mapping(address => uint) public lastBlock;
    mapping(address => mapping(bytes32 => bool)) public cookieIssued;
    uint public constant MAX_HALF_OPENS = 10;
    event SynCookieIssued(address indexed from, bytes32 cookie, TCPIPDefenseType defense);

    constructor() { owner = msg.sender; }

    /// issue SYN cookie and rate‑limit
    function syn(address to, uint16 port) external returns (bytes32 cookie) {
        // reset per‑block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            halfOpenCount[msg.sender] = 0;
        }
        // rate‑limit
        halfOpenCount[msg.sender]++;
        if (halfOpenCount[msg.sender] > MAX_HALF_OPENS) revert TCPIP__TooManyHalfOpens();

        // issue cookie
        cookie = keccak256(abi.encodePacked(msg.sender, to, port, block.timestamp));
        cookieIssued[msg.sender][cookie] = true;
        emit SynCookieIssued(msg.sender, cookie, TCPIPDefenseType.SYNCookie);
    }

    /// verify and clear one half‑open slot
    function verify(address from, bytes32 cookie) external {
        require(cookieIssued[from][cookie], "bad cookie");
        halfOpenCount[from]--;
        delete cookieIssued[from][cookie];
    }
}

////////////////////////////////////////////////////////////////////////
// 3) IP FRAGMENT OVERLAP
//
//  • Vulnerable: naive reassembly allows overlapping fragments to overwrite
//  • Attack: overlapping fragment exploit
//  • Defense: strict no‑overlap reassembly
////////////////////////////////////////////////////////////////////////
contract IPFragVuln {
    mapping(bytes32 => bytes) public buffer; // key = packet ID
    event Reassembled(bytes32 id, bytes payload);

    /// ❌ naively concatenates fragments
    function fragment(bytes32 id, bytes calldata frag) external {
        buffer[id] = bytes.concat(buffer[id], frag);
    }
    function assemble(bytes32 id) external {
        emit Reassembled(id, buffer[id]);
    }
}

contract Attack_FragOverlap {
    IPFragVuln public target;
    constructor(IPFragVuln _t) { target = _t; }

    function overlap(bytes32 id, bytes calldata f1, bytes calldata f2) external {
        target.fragment(id, f1);
        target.fragment(id, f2); // overlaps previous
        target.assemble(id);
    }
}

contract IPFragSafe {
    mapping(bytes32 => uint) public filled;
    mapping(bytes32 => bytes) public buffer;
    error TCPIP__OverlapDetected();

    /// strict reassembly: reject overlapping writes
    function fragment(bytes32 id, uint offset, bytes calldata frag) external {
        uint len = frag.length;
        // ensure new region [offset, offset+len) does not overlap filled
        uint filledEnd = filled[id];
        if (offset < filledEnd) revert TCPIP__OverlapDetected();
        // append
        buffer[id] = bytes.concat(buffer[id], frag);
        filled[id] = offset + len;
    }
    function assemble(bytes32 id) external {
        emit Reassembled(id, buffer[id]);
    }
    event Reassembled(bytes32 id, bytes payload);
}

////////////////////////////////////////////////////////////////////////
// 4) TTL MANIPULATION
//
//  • Vulnerable: trusts packet.ttl naively
//  • Attack: send packets with TTL too low to drop prematurely
//  • Defense: enforce minimum TTL
////////////////////////////////////////////////////////////////////////
contract TTLVuln {
    struct Packet { address src; address dst; uint8 ttl; bytes data; }
    event Forwarded(address src, address dst, bytes data);

    /// ❌ forwards based on provided ttl
    function forward(Packet calldata p) external {
        if (p.ttl == 0) revert("dropped");
        emit Forwarded(p.src, p.dst, p.data);
    }
}

contract Attack_TTLManipulation {
    TTLVuln public target;
    constructor(TTLVuln _t) { target = _t; }

    function sendLowTTL(address dst) external {
        TTLVuln.Packet memory p = TTLVuln.Packet({
            src: msg.sender,
            dst: dst,
            ttl: 0,
            data: ""
        });
        target.forward(p);
    }
}

contract TTLSafe {
    uint8 public constant MIN_TTL = 16;
    event Forwarded(address src, address dst, bytes data);
    error TCPIP__TTLTooLow();

    /// ✅ enforce minimum TTL
    function forward(address src, address dst, uint8 ttl, bytes calldata data) external {
        if (ttl < MIN_TTL) revert TCPIP__TTLTooLow();
        emit Forwarded(src, dst, data);
    }
}
