// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureBasedBinding {
    using ECDSA for bytes32;

    mapping(address => string) public boundIdentity;
    mapping(address => bool) public alreadyBound;

    address public signer;

    event IdentityBound(address indexed user, string identity);

    constructor(address _signer) {
        signer = _signer;
    }

    /**
     * @notice Bind an off-chain approved identity to your wallet.
     * @param name The identity string to bind (e.g., "alice123").
     * @param nonce Unique nonce to prevent replay attacks.
     * @param sig Signature from the trusted signer (backend).
     */
    function bindWithSig(
        string calldata name,
        uint256 nonce,
        bytes calldata sig
    ) public {
        require(!alreadyBound[msg.sender], "Already bound");

        bytes32 hash = keccak256(abi.encodePacked(msg.sender, name, nonce));
        bytes32 ethSigned = hash.toEthSignedMessageHash();

        require(ethSigned.recover(sig) == signer, "Invalid signature");

        boundIdentity[msg.sender] = name;
        alreadyBound[msg.sender] = true;

        emit IdentityBound(msg.sender, name);
    }

    /**
     * @notice Retrieve your own bound identity.
     */
    function getMyIdentity() public view returns (string memory) {
        return boundIdentity[msg.sender];
    }
}
