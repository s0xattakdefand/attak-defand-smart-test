// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DTD FILL DEVICE DEMO
 * CNSSI-4009-2015 / NSA/CSS Manual 3-16 (COMSEC)
 *
 * Illustrates:
 *  1) FillDeviceVulnerable – insecurely stores plaintext COMSEC/TRANSEC keys.
 *  2) SecureFillDevice     – stores only pointers, enforces access control
 *                            and cryptographic request approval.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — FillDeviceVulnerable (⚠️ insecure)
----------------------------------------------------------------------------*/
contract FillDeviceVulnerable {
    struct KeyBundle {
        bytes32 comsecKey;
        bytes32 transecKey;
    }

    mapping(address => KeyBundle) public deviceKeys;
    event KeysLoaded(address indexed device, bytes32 comsecKey, bytes32 transecKey);
    event KeysTransferred(address indexed from, address indexed to, bytes32 comsecKey, bytes32 transecKey);

    /// Load plaintext keys for a device—no restrictions!
    function loadKeys(address device, bytes32 comsecKey, bytes32 transecKey) external {
        deviceKeys[device] = KeyBundle(comsecKey, transecKey);
        emit KeysLoaded(device, comsecKey, transecKey);
    }

    /// Transfer keys from your device to another—no checks!
    function transferKeys(address to) external {
        KeyBundle memory kb = deviceKeys[msg.sender];
        deviceKeys[to] = kb;
        emit KeysTransferred(msg.sender, to, kb.comsecKey, kb.transecKey);
    }

    /// Read any device’s keys in cleartext
    function getKeys(address device) external view returns (bytes32 comsecKey, bytes32 transecKey) {
        KeyBundle memory kb = deviceKeys[device];
        return (kb.comsecKey, kb.transecKey);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers for SecureFillDevice
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
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(toEthSignedMessageHash(h), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureFillDevice (✅ hardened)
----------------------------------------------------------------------------*/
contract SecureFillDevice is Ownable {
    using ECDSA for bytes32;

    /// Pointers to encrypted COMSEC/TRANSEC blobs stored off-chain.
    struct KeyPointer {
        bytes32 comsecPointer;
        bytes32 transecPointer;
    }

    // device → key pointers
    mapping(address => KeyPointer) private _keyPointers;
    // which addresses are authorized to request keys
    mapping(address => bool) public authorizedDevices;

    event DeviceAuthorized(address indexed device);
    event KeysLoaded(address indexed device, bytes32 comsecPointer, bytes32 transecPointer);
    event KeyRequested(address indexed requester, address indexed device, bytes32 requestHash);

    /// Owner authorizes a device to pull keys.
    function authorizeDevice(address device) external onlyOwner {
        authorizedDevices[device] = true;
        emit DeviceAuthorized(device);
    }

    /// Load only the pointers/hashes to the encrypted keys; no plaintext on-chain.
    function loadKeyPointers(
        address device,
        bytes32 comsecPointer,
        bytes32 transecPointer
    ) external onlyOwner {
        _keyPointers[device] = KeyPointer(comsecPointer, transecPointer);
        emit KeysLoaded(device, comsecPointer, transecPointer);
    }

    /**
     * @notice Request access to a device’s keys.
     * @dev The requester must supply an ECDSA signature by the owner over:
     *      (this contract address, requester, target device).
     *      On success, emits KeyRequested; off-chain infrastructure then
     *      delivers the encrypted blobs securely.
     */
    function requestKey(
        address device,
        bytes calldata ownerSig
    ) external {
        require(authorizedDevices[msg.sender], "Requester not authorized");
        // Reconstruct the expected signed message
        bytes32 msgHash = keccak256(abi.encodePacked(address(this), msg.sender, device));
        require(msgHash.recover(ownerSig) == owner(), "Invalid owner signature");
        emit KeyRequested(msg.sender, device, msgHash);
    }

    /**
     * @notice Retrieve the stored pointers for a device.
     * @dev Only the device itself or an authorized requester may call.
     */
    function getKeyPointers(address device)
        external
        view
        returns (bytes32 comsecPointer, bytes32 transecPointer)
    {
        require(
            msg.sender == device || authorizedDevices[msg.sender],
            "Access denied"
        );
        KeyPointer memory kp = _keyPointers[device];
        return (kp.comsecPointer, kp.transecPointer);
    }
}
