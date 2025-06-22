// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/StorageSlot.sol";

contract CCIComponentVault {
    using ECDSA for bytes32;

    bytes32 private constant CCI_SLOT = keccak256("cci.component.slot");
    bytes32 private constant USED_SLOT = keccak256("cci.component.used");
    address public immutable trustedSigner;
    uint256 public expiryBlock;

    event AccessGranted(address indexed user);
    event CCIUsed(address indexed by);
    event CCIRotated(bytes32 newCCIHash);
    event CCIZeroized();

    constructor(bytes32 _cciHash, address _signer, uint256 _expiryBlock) {
        StorageSlot.getBytes32Slot(CCI_SLOT).value = _cciHash;
        trustedSigner = _signer;
        expiryBlock = _expiryBlock;
    }

    modifier notExpired() {
        require(block.number <= expiryBlock, "CCI: expired");
        _;
    }

    modifier notUsed() {
        require(!StorageSlot.getBooleanSlot(USED_SLOT).value, "CCI: already used");
        _;
    }

    function accessCCI(string calldata secret, bytes calldata signature)
        external
        notExpired
        notUsed
    {
        bytes32 hash = keccak256(abi.encodePacked(secret)).toEthSignedMessageHash();
        require(hash.recover(signature) == trustedSigner, "CCI: invalid signer");

        require(
            keccak256(abi.encodePacked(secret)) == StorageSlot.getBytes32Slot(CCI_SLOT).value,
            "CCI: secret mismatch"
        );

        StorageSlot.getBooleanSlot(USED_SLOT).value = true;

        emit AccessGranted(msg.sender);
        emit CCIUsed(msg.sender);
    }

    function rotateCCI(bytes32 newHash) external {
        require(msg.sender == trustedSigner, "Not authorized");
        StorageSlot.getBytes32Slot(CCI_SLOT).value = newHash;
        StorageSlot.getBooleanSlot(USED_SLOT).value = false;
        emit CCIRotated(newHash);
    }

    function zeroizeCCI() external {
        require(msg.sender == trustedSigner, "Not authorized");
        StorageSlot.getBytes32Slot(CCI_SLOT).value = bytes32(0);
        StorageSlot.getBooleanSlot(USED_SLOT).value = true;
        emit CCIZeroized();
    }
}
