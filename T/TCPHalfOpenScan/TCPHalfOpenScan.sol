// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TCPHalfOpenScanSuite.sol
/// @notice On‑chain analogues of “TCP Half‑Open Scan” (aka SYN scan) patterns:
///   • Types: ScanType, AttackType, DefenseType  
///   • Attack: SynFlood  
///   • Defense: SynCookie, RateLimit  

enum TCPHalfOpenScanType    { SynScan }
enum TCPHalfOpenAttackType  { SynFlood }
enum TCPHalfOpenDefenseType { SynCookie, RateLimit }

error TCPH__NotAllowed();
error TCPH__TooManyHalfOpens();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE: naive SYN scan logging (no state cleanup, no limits)
////////////////////////////////////////////////////////////////////////
contract TCPHalfOpenScanVuln {
    event SynScanned(
        address indexed scanner,
        address indexed target,
        uint16           port,
        TCPHalfOpenScanType scanType,
        TCPHalfOpenAttackType attackType
    );

    /// anyone may issue a “SYN” scan; never tracks or cleans up half‑opens
    function synScan(address target, uint16 port) external {
        emit SynScanned(
            msg.sender,
            target,
            port,
            TCPHalfOpenScanType.SynScan,
            TCPHalfOpenAttackType.SynFlood
        );
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB: flood the vulnerable SYN scan to exhaust logs/gas
////////////////////////////////////////////////////////////////////////
contract Attack_TCPHalfOpenScan {
    TCPHalfOpenScanVuln public target;
    event AttackExecuted(TCPHalfOpenAttackType attackType, uint16 port);

    constructor(TCPHalfOpenScanVuln _t) {
        target = _t;
    }

    /// attacker floods scans on a list of ports
    function synFlood(address dst, uint16[] calldata ports) external {
        for (uint i = 0; i < ports.length; i++) {
            target.synScan(dst, ports[i]);
            emit AttackExecuted(TCPHalfOpenAttackType.SynFlood, ports[i]);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE: defend with SYN cookies and rate‑limit half‑opens per scanner
////////////////////////////////////////////////////////////////////////
contract TCPHalfOpenScanSafe {
    address public owner;
    event SynScannedDefended(
        address indexed scanner,
        address indexed target,
        uint16           port,
        TCPHalfOpenScanType scanType,
        TCPHalfOpenDefenseType defenseType
    );

    // track active half‑opens per scanner → cookie issued, auto‑cleans in verify()
    mapping(address => uint256) public halfOpenCount;
    uint256 public constant MAX_HALF_OPENS = 10;

    // simple cookie store: mapping cookie → scanner
    mapping(bytes32 => address) private _cookies;

    constructor() {
        owner = msg.sender;
    }

    /// whitelist scanners
    function setAllowedScanner(address who, bool ok) external {
        require(msg.sender == owner, "only owner");
        // if ok==false, zero out any count
        if (!ok) halfOpenCount[who] = 0;
        // owner may manage list off‑chain
    }

    /// issue a SYN cookie instead of logging raw half‑open
    function synScan(address target, uint16 port) external returns (bytes32 cookie) {
        // rate‑limit per scanner
        uint256 cnt = halfOpenCount[msg.sender] + 1;
        if (cnt > MAX_HALF_OPENS) revert TCPH__TooManyHalfOpens();
        halfOpenCount[msg.sender] = cnt;

        // generate simple cookie tied to msg.sender/target/port/timestamp
        cookie = keccak256(abi.encodePacked(msg.sender, target, port, block.timestamp));
        _cookies[cookie] = msg.sender;

        emit SynScannedDefended(
            msg.sender,
            target,
            port,
            TCPHalfOpenScanType.SynScan,
            TCPHalfOpenDefenseType.SynCookie
        );
    }

    /// later, the scanner presents its cookie to verify and clear half‑open
    function verifyCookie(bytes32 cookie) external {
        address scanner = _cookies[cookie];
        require(scanner == msg.sender, "bad cookie");
        // clear one half‑open slot
        halfOpenCount[msg.sender] -= 1;
        delete _cookies[cookie];
        emit SynScannedDefended(
            msg.sender,
            address(0),
            0,
            TCPHalfOpenScanType.SynScan,
            TCPHalfOpenDefenseType.RateLimit
        );
    }
}
