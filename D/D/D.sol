// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ───────────  OpenZeppelin v5 imports  ─────────── */
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/* ───────────  SignedPayloadRegistry  ─────────────
 * Implements the NIST SP 800-102 idea of a “payload” that always includes
 * {message, signature, ≥1 timestamp}.  The contract verifies the ECDSA
 * signature and stores a tamper-proof digest on-chain.
 */
contract SignedPayloadRegistry is
    Ownable,          // needs constructor arg in OZ v5
    Pausable,
    ReentrancyGuard
{
    using ECDSA for bytes32;   // for .recover()

    /* ─────  Data model  ───── */
    struct Payload {
        address  signer;
        bytes    message;
        uint64[] timestamps;
        bytes32  digest;
        uint40   storedAt;
    }

    /* digest ⇒ payload */
    mapping(bytes32 => Payload) private _payloads;

    event PayloadStored(
        bytes32 indexed digest,
        address indexed signer,
        bytes    message,
        uint64[] timestamps
    );

    /* ─────  Constructor  ───── */
    constructor() Ownable(msg.sender) { }   // set deployer as owner

    /* ─────  Public API  ───── */
    function submitPayload(
        bytes calldata   message,
        uint64[] calldata timestamps,   // must contain ≥ 1 entry
        bytes calldata   signature
    )
        external
        whenNotPaused
        nonReentrant
    {
        require(timestamps.length > 0, "need >=1 timestamp");

        /* Build deterministic digest of (message, timestamps, signer) */
        bytes32 digest = keccak256(
            abi.encode(message, timestamps, msg.sender)
        );
        require(_payloads[digest].storedAt == 0, "digest already stored");

        /* Verify ECDSA signature (v5 style) */
        bytes32 ethHash =
            MessageHashUtils.toEthSignedMessageHash(digest);
        address recovered = ethHash.recover(signature);
        require(recovered == msg.sender, "bad signature");

        /* Persist & emit */
        _payloads[digest] = Payload({
            signer:     msg.sender,
            message:    message,
            timestamps: timestamps,
            digest:     digest,
            storedAt:   uint40(block.timestamp)
        });
        emit PayloadStored(digest, msg.sender, message, timestamps);
    }

    function getPayload(bytes32 digest)
        external
        view
        returns (Payload memory)
    {
        require(_payloads[digest].storedAt != 0, "unknown digest");
        return _payloads[digest];
    }

    /* ─────  Admin ops  ───── */
    function pause()   external onlyOwner { _pause(); }
    function unpause() external onlyOwner { _unpause(); }
}
