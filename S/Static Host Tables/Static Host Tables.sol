// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StaticHostTableSuite.sol
/// @notice Four “Static Host Table” patterns illustrating common pitfalls
///         in manual host→IP mappings, plus hardened defenses.

error SHT__NotOwner();
error SHT__EntryExists();
error SHT__TooManyEntries();
error SHT__EntryExpired();

//////////////////////////////////////////////
// 1) UNRESTRICTED HOST ADDITION
//
//  • Type: anyone may add or update host→IP entries
//  • Attack: register malicious DNS entries for others
//  • Defense: restrict add/update to owner only
//////////////////////////////////////////////
contract HostTableVuln1 {
    mapping(string => address) public hosts;
    function setHost(string calldata name, address ip) external {
        hosts[name] = ip;
    }
}

contract Attack_HostTable1 {
    HostTableVuln1 public tbl;
    constructor(HostTableVuln1 _t) { tbl = _t; }
    function hijack(string calldata victim, address evil) external {
        tbl.setHost(victim, evil);
    }
}

contract HostTableSafe1 {
    mapping(string => address) public hosts;
    address public immutable owner;
    event HostSet(string name, address ip);

    constructor() { owner = msg.sender; }

    function setHost(string calldata name, address ip) external {
        if (msg.sender != owner) revert SHT__NotOwner();
        hosts[name] = ip;
        emit HostSet(name, ip);
    }
}

//////////////////////////////////////////////
// 2) UNAUTHORIZED OVERRIDE
//
//  • Type: existing entries may be overwritten by any caller
//  • Attack: override a correct entry after it's set
//  • Defense: allow first‐come‐first‐served only (no override)
//////////////////////////////////////////////
contract HostTableVuln2 {
    mapping(string => address) public hosts;
    function register(string calldata name, address ip) external {
        hosts[name] = ip;
    }
}

contract Attack_HostOverride {
    HostTableVuln2 public tbl;
    constructor(HostTableVuln2 _t) { tbl = _t; }
    function overrideEntry(string calldata name, address evil) external {
        tbl.register(name, evil);
    }
}

contract HostTableSafe2 {
    mapping(string => address) public hosts;
    error SHT__EntryExists();
    event HostRegistered(string name, address ip);

    function register(string calldata name, address ip) external {
        if (hosts[name] != address(0)) revert SHT__EntryExists();
        hosts[name] = ip;
        emit HostRegistered(name, ip);
    }
}

//////////////////////////////////////////////
// 3) HOST TABLE FLOODING (DoS)
// 
//  • Type: unbounded number of entries → enumeration or forwarding DOS
//  • Attack: spam thousands of host names
//  • Defense: cap total number of entries
//////////////////////////////////////////////
contract HostTableVuln3 {
    struct Entry { string name; address ip; }
    Entry[] public entries;
    mapping(string => address) public hosts;

    function addHost(string calldata name, address ip) external {
        hosts[name] = ip;
        entries.push(Entry(name, ip));
    }
}

contract Attack_HostFlood {
    HostTableVuln3 public tbl;
    constructor(HostTableVuln3 _t) { tbl = _t; }
    function flood(string[] calldata names, address ip) external {
        for (uint i = 0; i < names.length; i++) {
            tbl.addHost(names[i], ip);
        }
    }
}

contract HostTableSafe3 {
    struct Entry { string name; address ip; }
    Entry[] public entries;
    mapping(string => address) public hosts;
    uint256 public constant MAX_ENTRIES = 100;
    error SHT__TooManyEntries();
    event HostAdded(string name, address ip);

    function addHost(string calldata name, address ip) external {
        if (entries.length >= MAX_ENTRIES) revert SHT__TooManyEntries();
        hosts[name] = ip;
        entries.push(Entry(name, ip));
        emit HostAdded(name, ip);
    }
}

//////////////////////////////////////////////
// 4) STALE HOST EXPIRY
//
//  • Type: entries never expire → outdated mappings persist
//  • Attack: stale IPs continue to resolve long after deprecation
//  • Defense: attach TTL and reject expired entries
//////////////////////////////////////////////
contract HostTableVuln4 {
    mapping(string => address) public hosts;
    function setHost(string calldata name, address ip) external {
        hosts[name] = ip;
    }
    function getHost(string calldata name) external view returns (address) {
        return hosts[name];
    }
}

contract Attack_HostStale {
    HostTableVuln4 public tbl;
    constructor(HostTableVuln4 _t) { tbl = _t; }
    function readStale(string calldata name) external view returns (address) {
        return tbl.getHost(name);
    }
}

contract HostTableSafe4 {
    struct Entry { address ip; uint256 expiry; }
    mapping(string => Entry) public hosts;
    error SHT__EntryExpired();
    event HostSet(string name, address ip, uint256 expiry);

    /// @notice set a host with a TTL (in seconds)
    function setHost(string calldata name, address ip, uint256 ttl) external {
        uint256 exp = block.timestamp + ttl;
        hosts[name] = Entry(ip, exp);
        emit HostSet(name, ip, exp);
    }

    /// @notice get host only if not expired
    function getHost(string calldata name) external view returns (address) {
        Entry memory e = hosts[name];
        if (e.expiry < block.timestamp) revert SHT__EntryExpired();
        return e.ip;
    }
}
