// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract CCIEquipmentManager is Ownable {
    using ECDSA for bytes32;

    address public trustedSigner;
    bytes32 private secretHash;
    bool public used;
    uint256 public validUntil;

    event AccessGranted(address user);
    event KeyRotated(address newSigner, bytes32 newHash);
    event SecretZeroized();

    constructor(address _signer, bytes32 _hash, uint256 _validUntil) {
        trustedSigner = _signer;
        secretHash = _hash;
        validUntil = _validUntil;
    }

    function accessCCI(string calldata secret, bytes calldata sig) external {
        require(!used, "CCI: already used");
        require(block.timestamp < validUntil, "CCI: expired");

        bytes32 digest = keccak256(abi.encodePacked(secret)).toEthSignedMessageHash();
        address recovered = digest.recover(sig);
        require(recovered == trustedSigner, "Invalid signer");
        require(keccak256(abi.encodePacked(secret)) == secretHash, "Invalid secret");

        used = true;
        emit AccessGranted(msg.sender);
    }

    function rotateKey(address newSigner, bytes32 newHash, uint256 newExpiry) external onlyOwner {
        trustedSigner = newSigner;
        secretHash = newHash;
        used = false;
        validUntil = newExpiry;
        emit KeyRotated(newSigner, newHash);
    }

    function zeroizeSecret() external onlyOwner {
        secretHash = 0x0;
        used = true;
        emit SecretZeroized();
    }
}
