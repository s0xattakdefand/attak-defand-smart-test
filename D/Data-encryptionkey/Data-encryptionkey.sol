// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATA ENCRYPTION KEY (DEK) MANAGER DEMO
 * NIST SP 800-57 Part 1 Rev. 5 — “A key used to encrypt and decrypt data other than keys.”
 *
 * This file shows two contracts:
 *  1) VulnerableDEKStore   — insecurely stores raw DEKs on-chain.
 *  2) SecureDEKPointerVault — stores only pointers to encrypted DEKs off-chain,
 *                             enforces access control, and logs all actions.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDEKStore (⚠️ insecure)
----------------------------------------------------------------------------*/
contract VulnerableDEKStore {
    mapping(address => bytes32) public dataEncryptionKey;
    event DEKSet(address indexed owner, bytes32 dek);
    event DEKRetrieved(address indexed owner, address indexed requester, bytes32 dek);

    /// Stores the raw DEK on-chain (no access control!)
    function setDEK(bytes32 dek) external {
        dataEncryptionKey[msg.sender] = dek;
        emit DEKSet(msg.sender, dek);
    }

    /// Anyone can retrieve any owner’s DEK
    function getDEK(address owner) external returns (bytes32) {
        bytes32 dek = dataEncryptionKey[owner];
        emit DEKRetrieved(owner, msg.sender, dek);
        return dek;
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers for SecureDEKPointerVault
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
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset,32))
            v := byte(0, calldataload(add(sig.offset,64)))
        }
        return ecrecover(toEthSignedMessageHash(h), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureDEKPointerVault (✅ hardened)
----------------------------------------------------------------------------*/
contract SecureDEKPointerVault is Ownable {
    using ECDSA for bytes32;

    /// Each owner’s DEK is stored off-chain encrypted; on-chain we keep only a pointer (e.g., IPFS CID hash)
    mapping(address => bytes32) private _encryptedDEKPointer;
    /// Which callers are authorized to request a given owner’s DEK
    mapping(address => mapping(address => bool)) private _authorizedRequesters;

    event DEKPointerLoaded(address indexed owner, bytes32 pointer);
    event RequesterAuthorized(address indexed owner, address indexed requester);
    event DEKPointerRequested(address indexed owner, address indexed requester, bytes32 requestHash);

    /// Owner loads only the pointer to their encrypted DEK; no raw key on-chain
    function loadEncryptedDEKPointer(bytes32 pointerHash) external {
        _encryptedDEKPointer[msg.sender] = pointerHash;
        emit DEKPointerLoaded(msg.sender, pointerHash);
    }

    /// Owner authorizes an off-chain service or user to request their DEK
    function authorizeRequester(address requester) external {
        _authorizedRequesters[msg.sender][requester] = true;
        emit RequesterAuthorized(msg.sender, requester);
    }

    /**
     * @notice Request the DEK pointer for a given owner.
     * @dev Caller must be authorized by that owner and supply the owner’s signature
     *      over (contract, requester address, owner address).
     */
    function requestDEKPointer(
        address ownerAddr,
        bytes calldata ownerSig
    ) external {
        require(_authorizedRequesters[ownerAddr][msg.sender], "Not authorized to request");
        // Recreate signed message hash
        bytes32 msgHash = keccak256(abi.encodePacked(address(this), msg.sender, ownerAddr));
        require(msgHash.recover(ownerSig) == ownerAddr, "Invalid owner signature");
        emit DEKPointerRequested(ownerAddr, msg.sender, msgHash);
    }

    /**
     * @notice Retrieve the encrypted DEK pointer for a given owner.
     * @dev Only the owner themselves or an authorized requester may call.
     */
    function getEncryptedDEKPointer(address ownerAddr) external view returns (bytes32) {
        require(
            msg.sender == ownerAddr || _authorizedRequesters[ownerAddr][msg.sender],
            "Access denied"
        );
        return _encryptedDEKPointer[ownerAddr];
    }
}
