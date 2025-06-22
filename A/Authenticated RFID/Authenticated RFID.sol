// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticatedRFIDRegistry - Verifies RFID tag authenticity on-chain

contract AuthenticatedRFIDRegistry {
    address public owner;

    struct RFIDTag {
        bytes32 tagID;
        address publicKey;
        bool registered;
    }

    mapping(bytes32 => RFIDTag) public tags;
    mapping(bytes32 => bool) public usedNonces;

    event RFIDAuthenticated(bytes32 indexed tagID, string context, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Register a new RFID tag with its public key
    function registerTag(bytes32 tagID, address pubKey) external onlyOwner {
        require(!tags[tagID].registered, "Already registered");
        tags[tagID] = RFIDTag(tagID, pubKey, true);
    }

    /// @notice Authenticate an RFID-signed payload (e.g., at a checkpoint)
    /// @param tagID RFID tag identifier
    /// @param nonce One-time value to prevent replay
    /// @param context Label describing this authentication event
    /// @param signature Signed hash of (tagID || nonce || context)
    function authenticateRFID(
        bytes32 tagID,
        bytes32 nonce,
        string calldata context,
        bytes calldata signature
    ) external {
        require(tags[tagID].registered, "Unknown tag");
        require(!usedNonces[nonce], "Replay detected");

        bytes32 digest = keccak256(abi.encodePacked(tagID, nonce, context));
        address signer = recoverSigner(digest, signature);
        require(signer == tags[tagID].publicKey, "Invalid tag signature");

        usedNonces[nonce] = true;

        emit RFIDAuthenticated(tagID, context, block.timestamp);
    }

    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Bad signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
