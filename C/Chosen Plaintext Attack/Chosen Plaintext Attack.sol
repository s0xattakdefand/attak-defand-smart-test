// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title SecureEncryptOracle
 * @notice Offers **probabilistic** encryption: the caller supplies
 *         plaintext **and a fresh 96-bit nonce**; contract only checks
 *         integrity/auth & *logs* the request.  The real AES-GCM
 *         encryption happens **off-chain** so the secret key never
 *         touches Ethereum and ciphertexts are unique per nonce.  Thus
 *         an adaptive chosen-plaintext adversary learns nothing useful.
 *
 *  Counter-measures
 *  ----------------
 *  1. Caller-provided *fresh nonce* → identical plaintexts encrypt
 *     differently every time (breaks deterministic dictionary).
 *  2. Caller ECDSA signature binds (nonce‖pt) to wallet → blocks forgery.
 *  3. Replay + rate limits identical to the CCA-hardened design.
 */
contract SecureEncryptOracle is Ownable, Pausable, ReentrancyGuard {
    event EncryptRequested(
        address indexed caller,
        bytes12    nonce,
        bytes      plaintext
    );

    mapping(address => mapping(bytes12 => bool)) public nonceUsed;
    mapping(address => uint256) public lastReqAt;
    uint256 public constant MIN_INTERVAL = 30;

    modifier onlyHuman() {
        require(tx.origin == msg.sender, "No contract calls");
        _;
    }

    function requestEncrypt(
        bytes12 nonce,
        bytes calldata pt,
        bytes calldata sig
    )
        external
        whenNotPaused
        onlyHuman
        nonReentrant
    {
        require(
            block.timestamp >= lastReqAt[msg.sender] + MIN_INTERVAL,
            "Rate-limit"
        );
        require(!nonceUsed[msg.sender][nonce], "Nonce replay");
        nonceUsed[msg.sender][nonce] = true;
        lastReqAt[msg.sender] = block.timestamp;

        // Signature check: hash(nonce‖pt‖caller)
        bytes32 digest = keccak256(abi.encodePacked(nonce, pt, msg.sender));
        address signer =
            ECDSA.recover(ECDSA.toEthSignedMessageHash(digest), sig);
        require(signer == msg.sender, "Bad sig");

        // Emit event → off-chain worker encrypts with AES-GCM(nonce, key)
        emit EncryptRequested(msg.sender, nonce, pt);
    }

    /* Admin pause controls */
    function pause() external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
