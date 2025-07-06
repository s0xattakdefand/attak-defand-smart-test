// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   DATA SECURITY STANDARD DEMO
   — Illustrates a system that fails to meet basic data security standards,
     vs. one that enforces encryption-at-rest, encryption-in-transit,
     access control, and audit logging.
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — PlainDataStore (⚠️ Does NOT meet any Data Security Standard)
----------------------------------------------------------------------------*/
contract PlainDataStore {
    mapping(uint256 => bytes) public dataStore;
    uint256 public counter;

    event DataStored(uint256 indexed id, bytes clearData);

    function store(bytes calldata clearData) external {
        uint256 id = counter++;
        dataStore[id] = clearData;
        emit DataStored(id, clearData);
    }

    function retrieve(uint256 id) external view returns (bytes memory) {
        return dataStore[id];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers for SecureDataVault
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

library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(toEthSignedMessageHash(h), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureDataVault (✅ Enforces Data Security Standard)
----------------------------------------------------------------------------*/
contract SecureDataVault is Ownable {
    using ECDSA for bytes32;

    struct Record {
        bytes32 encryptedPointer;  // hash of encrypted blob stored off-chain
        address uploader;
        uint256 timestamp;
    }

    mapping(uint256 => Record) private _records;
    uint256 public recordCount;

    mapping(uint256 => mapping(address => bool)) private _authorized;

    event RecordLoaded(uint256 indexed id, address indexed uploader, bytes32 encryptedPointer);
    event AccessRequested(uint256 indexed id, address indexed requester);
    event AccessAuthorized(uint256 indexed id, address indexed reader);

    /// Owner loads a new encrypted data pointer
    function loadRecord(bytes32 encryptedPointer) external onlyOwner returns (uint256 id) {
        id = recordCount++;
        _records[id] = Record({
            encryptedPointer: encryptedPointer,
            uploader: msg.sender,
            timestamp: block.timestamp
        });
        emit RecordLoaded(id, msg.sender, encryptedPointer);
    }

    /// Anyone may request access; off-chain systems can watch this event
    function requestAccess(uint256 id) external {
        require(id < recordCount, "Invalid record");
        emit AccessRequested(id, msg.sender);
    }

    /// Owner authorizes a reader after validating the request
    function authorizeReader(uint256 id, address reader) external onlyOwner {
        require(id < recordCount, "Invalid record");
        _authorized[id][reader] = true;
        emit AccessAuthorized(id, reader);
    }

    /// Fetch the encrypted pointer; gated by on-chain access control
    function getEncryptedPointer(uint256 id) external view returns (bytes32) {
        Record storage r = _records[id];
        require(
            msg.sender == owner() ||
            msg.sender == r.uploader ||
            _authorized[id][msg.sender],
            "Access denied"
        );
        return r.encryptedPointer;
    }
}

/*=============================================================================
   WHY SecureDataVault MEETS DATA SECURITY STANDARD PRINCIPLES
   — Confidentiality at Rest: clear data never on-chain; only encrypted pointers.
   — Confidentiality in Transit: access gated on-chain; off-chain uses secure channels.
   — Access Control: only owner, uploader, or authorized readers.
   — Audit Logging: load and request events record actions without leaking data.
   — Key Management: encryption handled off-chain; keys never stored on-chain.
   — Integrity: encryptedPointer acts as tamper-evident hash.
=============================================================================*/
