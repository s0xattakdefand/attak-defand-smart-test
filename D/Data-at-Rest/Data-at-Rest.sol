// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   DATA-AT-REST DEMO
   — “Data-at-Rest” refers to data stored in any non‐transitory medium.
     This file contrasts:
       1) VulnerableDataAtRest — stores plaintext blobs on-chain with no controls.
       2) SecureDataAtRest     — stores only encrypted‐blob pointers, with access
                                control and audit logging.
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDataAtRest (⚠️ insecure)
   • Stores full data in contract storage.
   • Emits data in events (logs forever).
   • No access control ⇒ anyone can read or overwrite.
----------------------------------------------------------------------------*/
contract VulnerableDataAtRest {
    mapping(uint256 => bytes) public store;
    uint256 public counter;

    event DataStored(uint256 indexed id, bytes data);

    /// Store arbitrary data in cleartext
    function storeData(bytes calldata data) external {
        uint256 id = counter++;
        store[id] = data;
        emit DataStored(id, data);
    }

    /// Anyone can read any stored data
    function readData(uint256 id) external view returns (bytes memory) {
        return store[id];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Ownable helper
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: not owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureDataAtRest (✅ hardened)
   • Only stores encrypted‐blob pointers (e.g., IPFS CIDs or off‐chain URLs).
   • Access control: only owner and authorized readers may retrieve pointers.
   • Audit events log all load and access operations without leaking data.
----------------------------------------------------------------------------*/
contract SecureDataAtRest is Ownable {
    // Mapping of record ID → encrypted‐blob pointer hash
    mapping(uint256 => bytes32) private _pointers;
    uint256 public recordCount;

    // RecordID → reader → authorized?
    mapping(uint256 => mapping(address => bool)) private _authorized;

    event PointerStored(uint256 indexed id, bytes32 pointerHash);
    event ReaderAuthorized(uint256 indexed id, address indexed reader);
    event PointerAccessed(uint256 indexed id, address indexed accessor);

    /// Owner stores only the hash/pointer of the encrypted blob
    function storePointer(bytes32 pointerHash) external onlyOwner returns (uint256 id) {
        id = recordCount++;
        _pointers[id] = pointerHash;
        emit PointerStored(id, pointerHash);
    }

    /// Owner authorizes a reader to access a given pointer
    function authorizeReader(uint256 id, address reader) external onlyOwner {
        require(id < recordCount, "Invalid record");
        _authorized[id][reader] = true;
        emit ReaderAuthorized(id, reader);
    }

    /// Retrieve the pointer; only owner or authorized readers may call
    function getPointer(uint256 id) external returns (bytes32) {
        require(id < recordCount, "Invalid record");
        require(
            msg.sender == owner() || _authorized[id][msg.sender],
            "Access denied"
        );
        emit PointerAccessed(id, msg.sender);
        return _pointers[id];
    }
}
