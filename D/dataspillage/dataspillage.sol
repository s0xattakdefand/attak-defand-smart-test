// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   SPILLAGE DEMO
   CNSSI-4009-2015 — “Security incident that results in the transfer of
   classified information onto an information system not authorized to store
   or process that information” (spillage)
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableSpillageStore (⚠️ no spillage controls)
   • Any caller may upload data of any classification.
   • No tracking of system clearance; no detection of spillage incidents.
----------------------------------------------------------------------------*/
contract VulnerableSpillageStore {
    enum Classification { UNCLASSIFIED, CONFIDENTIAL, SECRET, TOPSECRET }

    struct Record {
        Classification cls;
        bytes data;
        address uploader;
        uint256 timestamp;
    }

    Record[] public records;

    event DataUploaded(uint256 indexed id, Classification cls, address indexed uploader);

    /// Anyone can upload any classified data (no clearance checks).
    function uploadData(Classification cls, bytes calldata data) external {
        records.push(Record(cls, data, msg.sender, block.timestamp));
        emit DataUploaded(records.length - 1, cls, msg.sender);
    }

    /// Retrieve a record.
    function getRecord(uint256 id)
        external
        view
        returns (Classification cls, bytes memory data, address uploader, uint256 timestamp)
    {
        Record storage r = records[id];
        return (r.cls, r.data, r.uploader, r.timestamp);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Ownable helper (for SecureSpillageGuard)
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    constructor() { _owner = msg.sender; emit OwnershipTransferred(address(0), _owner); }
    modifier onlyOwner() { require(msg.sender == _owner, "Ownable: not owner"); _; }
    function owner() public view returns(address) { return _owner; }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureSpillageGuard (✅ detects & prevents spillage)
   • Owner assigns clearance levels to authorized systems.
   • Systems call uploadSafe(); classification > clearance ⇒ spillage.
   • SpillageDetected event logged on violation; upload is reverted.
----------------------------------------------------------------------------*/
contract SecureSpillageGuard is Ownable {
    enum Classification { UNCLASSIFIED, CONFIDENTIAL, SECRET, TOPSECRET }

    // system address ⇒ maximum allowed classification
    mapping(address => Classification) private _clearance;

    struct Record {
        Classification cls;
        bytes data;
        address system;
        uint256 timestamp;
    }

    Record[] public records;

    event SystemRegistered(address indexed system, Classification clearance);
    event DataStored(uint256 indexed id, Classification cls, address indexed system);
    event SpillageDetected(address indexed system, Classification attempted, uint256 timestamp);

    /// Owner registers a system with its maximum clearance level.
    function registerSystem(address system, Classification clearance) external onlyOwner {
        _clearance[system] = clearance;
        emit SystemRegistered(system, clearance);
    }

    /// Systems call this to upload data safely.
    /// If classification exceeds system clearance, spillage is detected and reverted.
    function uploadSafe(Classification cls, bytes calldata data) external {
        Classification sysClearance = _clearance[msg.sender];
        // default clearance is UNCLASSIFIED if unregistered
        if (cls > sysClearance) {
            emit SpillageDetected(msg.sender, cls, block.timestamp);
            revert("Spillage detected: insufficient clearance");
        }
        records.push(Record(cls, data, msg.sender, block.timestamp));
        emit DataStored(records.length - 1, cls, msg.sender);
    }

    /// Retrieve a stored record.
    function getRecord(uint256 id)
        external
        view
        returns (Classification cls, bytes memory data, address system, uint256 timestamp)
    {
        Record storage r = records[id];
        return (r.cls, r.data, r.system, r.timestamp);
    }

    /// Returns the clearance level of a system.
    function systemClearance(address system) external view returns (Classification) {
        return _clearance[system];
    }
}
