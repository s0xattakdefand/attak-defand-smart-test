// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DYNAMIC DOMAIN NAME SYSTEM (DDNS) DEMO
 * — On-chain DNS registry with dynamic updates, expirations, and ownership transfers.
 *
 * Features:
 *  • Anyone can register an unclaimed or expired name for a given period.
 *  • Domain owners can update their records (e.g. IP address) and TTL.
 *  • Domain owners can transfer ownership.
 *  • Events log all registrations, updates, and transfers.
 */

contract DynamicDNS {
    struct Record {
        address owner;      // current domain owner
        string  value;      // e.g. “1.2.3.4” or a content hash
        uint256 expires;    // UNIX timestamp when registration lapses
        uint256 ttl;        // time-to-live in seconds
    }

    // nameHash = keccak256(abi.encodePacked(name))
    mapping(bytes32 => Record) private _records;

    event DomainRegistered(string indexed name, bytes32 indexed nameHash, address indexed owner, uint256 expires);
    event DomainUpdated(string indexed name, bytes32 indexed nameHash, string value, uint256 ttl);
    event DomainTransferred(string indexed name, bytes32 indexed nameHash, address indexed oldOwner, address newOwner);

    modifier onlyOwner(bytes32 nameHash) {
        require(msg.sender == _records[nameHash].owner, "DDNS: not owner");
        _;
    }

    /// @notice Register a domain for `duration` seconds if unclaimed or expired
    function registerDomain(string calldata name, uint256 duration) external {
        bytes32 nh = keccak256(abi.encodePacked(name));
        Record storage r = _records[nh];
        require(r.owner == address(0) || block.timestamp >= r.expires, "DDNS: name taken");
        r.owner   = msg.sender;
        r.expires = block.timestamp + duration;
        emit DomainRegistered(name, nh, msg.sender, r.expires);
    }

    /// @notice Update the record value and TTL for your domain
    function updateRecord(string calldata name, string calldata value, uint256 ttl) external {
        bytes32 nh = keccak256(abi.encodePacked(name));
        Record storage r = _records[nh];
        require(msg.sender == r.owner && block.timestamp < r.expires, "DDNS: unauthorized or expired");
        r.value = value;
        r.ttl   = ttl;
        emit DomainUpdated(name, nh, value, ttl);
    }

    /// @notice Transfer domain ownership
    function transferDomain(string calldata name, address newOwner) external {
        bytes32 nh = keccak256(abi.encodePacked(name));
        Record storage r = _records[nh];
        require(msg.sender == r.owner && block.timestamp < r.expires, "DDNS: unauthorized or expired");
        address old = r.owner;
        r.owner = newOwner;
        emit DomainTransferred(name, nh, old, newOwner);
    }

    /// @notice Resolve a name to its current value, owner, expiry, and TTL
    function resolve(string calldata name)
        external
        view
        returns (
            address owner,
            string memory value,
            uint256 expires,
            uint256 ttl
        )
    {
        bytes32 nh = keccak256(abi.encodePacked(name));
        Record storage r = _records[nh];
        require(r.owner != address(0) && block.timestamp < r.expires, "DDNS: not found or expired");
        return (r.owner, r.value, r.expires, r.ttl);
    }

    /// @notice Check whether a domain is available (unclaimed or expired)
    function isAvailable(string calldata name) external view returns (bool) {
        bytes32 nh = keccak256(abi.encodePacked(name));
        Record storage r = _records[nh];
        return (r.owner == address(0) || block.timestamp >= r.expires);
    }
}
