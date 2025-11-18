// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * ENDORSEMENT KEY SMART CONTRACT
 *
 * This single file contains:
 *  1) EndorsementKeyRegistry  – naive / semi-secure registry (has a weakness)
 *  2) EndorsementKeyAttacker  – attacker trying to abuse that weakness
 *  3) EndorsementKeyDefense   – hardened pattern with signature + nonce
 *
 * You can deploy all 3 from this single file.
 */

/// @title EndorsementKeyRegistry (basic / semi-secure)
/// @notice Registry mapping users -> their Endorsement Key (EK) addresses.
contract EndorsementKeyRegistry {
    struct EKRecord {
        address ek;            // current endorsement key
        bool revoked;
        uint64 createdAt;
        uint64 updatedAt;
    }

    // Owner (admin) of the registry
    address public owner;

    // user => EK record
    mapping(address => EKRecord) private records;

    // BAD PATTERN: using tx.origin for "admin-like" helper
    // This is what the attacker will try to exploit.
    bool public useTxOriginForAdmin; // toggle for educational purposes

    event EKRegistered(address indexed user, address ek);
    event EKRotated(address indexed user, address oldEk, address newEk);
    event EKRevoked(address indexed user, address ek);
    event AdminUpdated(address indexed oldOwner, address indexed newOwner);
    event UseTxOriginForAdminToggled(bool enabled);

    modifier onlyOwner() {
        // Vulnerable mode: using tx.origin (DO NOT USE IN REAL SYSTEMS)
        if (useTxOriginForAdmin) {
            require(tx.origin == owner, "not owner (tx.origin)");
        } else {
            require(msg.sender == owner, "not owner");
        }
        _;
    }

    modifier validEK(address ek) {
        require(ek != address(0), "EK zero");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Toggle vulnerable behavior using tx.origin (for attack demo).
    function toggleUseTxOriginForAdmin(bool enabled) external onlyOwner {
        useTxOriginForAdmin = enabled;
        emit UseTxOriginForAdminToggled(enabled);
    }

    /// @notice Admin can change owner (demonstrates tx.origin risk).
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        address old = owner;
        owner = newOwner;
        emit AdminUpdated(old, newOwner);
    }

    /// @notice User registers their own EK.
    function registerEK(address ek) external validEK(ek) {
        EKRecord storage r = records[msg.sender];
        require(r.ek == address(0), "EK exists");

        r.ek = ek;
        r.revoked = false;
        r.createdAt = uint64(block.timestamp);
        r.updatedAt = uint64(block.timestamp);

        emit EKRegistered(msg.sender, ek);
    }

    /// @notice User rotates EK to a new address.
    function rotateEK(address newEk) external validEK(newEk) {
        EKRecord storage r = records[msg.sender];
        require(!r.revoked, "revoked");
        require(r.ek != address(0), "no EK");

        address old = r.ek;
        r.ek = newEk;
        r.updatedAt = uint64(block.timestamp);

        emit EKRotated(msg.sender, old, newEk);
    }

    /// @notice User revokes current EK.
    function revokeEK() external {
        EKRecord storage r = records[msg.sender];
        require(r.ek != address(0), "no EK");
        require(!r.revoked, "already revoked");

        r.revoked = true;
        r.updatedAt = uint64(block.timestamp);

        emit EKRevoked(msg.sender, r.ek);
    }

    /// @notice View EK record for a user.
    function getEK(address user)
        external
        view
        returns (address ek, bool revoked, uint64 createdAt, uint64 updatedAt)
    {
        EKRecord storage r = records[user];
        return (r.ek, r.revoked, r.createdAt, r.updatedAt);
    }

    /// @notice Simple verify: is signer the active EK of user and not revoked?
    function verifyEK(address user, address signer) external view returns (bool) {
        EKRecord storage r = records[user];
        if (r.revoked || r.ek == address(0)) return false;
        return r.ek == signer;
    }
}

/* ============================================================= */
/*                     ATTACKER CONTRACT                         */
/* ============================================================= */

/// @title EndorsementKeyAttacker
/// @notice Demonstrates how using tx.origin in admin checks can be abused.
contract EndorsementKeyAttacker {
    EndorsementKeyRegistry public target;
    address public attacker;

    event AttackAttempted(address indexed attacker, bool success);

    constructor(address _registry) {
        target = EndorsementKeyRegistry(_registry);
        attacker = msg.sender;
    }

    /**
     * ATTACK IDEA:
     *  - Registry uses tx.origin for onlyOwner (if enabled).
     *  - Attacker deploys this contract and convinces the owner to call
     *    `attackTransferOwnership` (e.g. via phishing / malicious UI).
     *  - tx.origin == real owner, but msg.sender == this contract.
     *  - Because registry checks tx.origin (vulnerable mode), owner check passes.
     *  - Ownership of registry is transferred to attacker.
     */
    function attackTransferOwnership() external {
        // In a real phishing scenario, the *owner* is tricked to call this.
        // Here, we just demonstrate the call path.
        try target.transferOwnership(attacker) {
            emit AttackAttempted(attacker, true);
        } catch {
            emit AttackAttempted(attacker, false);
        }
    }
}

/* ============================================================= */
/*                         DEFENSE CONTRACT                      */
/* ============================================================= */

/// @title EndorsementKeyDefense
/// @notice Hardened Endorsement Key pattern with:
///  - Proper msg.sender-based admin
///  - ECDSA verification of Endorsement Key signatures
///  - Nonce to prevent replay
contract EndorsementKeyDefense {
    struct EKRecord {
        address ek;            // active endorsement key
        bool revoked;
        uint64 createdAt;
        uint64 updatedAt;
    }

    address public owner;
    mapping(address => EKRecord) private records;
    mapping(address => uint256) public nonces; // anti-replay per user

    event EKRegistered(address indexed user, address ek);
    event EKRotated(address indexed user, address oldEk, address newEk);
    event EKRevoked(address indexed user, address ek);
    event OwnerChanged(address indexed oldOwner, address indexed newOwner);
    event MessageVerified(address indexed user, address signer, uint256 nonce);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier validEK(address ek) {
        require(ek != address(0), "EK zero");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero");
        address old = owner;
        owner = newOwner;
        emit OwnerChanged(old, newOwner);
    }

    /// @notice User registers EK.
    function registerEK(address ek) external validEK(ek) {
        EKRecord storage r = records[msg.sender];
        require(r.ek == address(0), "EK exists");

        r.ek = ek;
        r.revoked = false;
        r.createdAt = uint64(block.timestamp);
        r.updatedAt = uint64(block.timestamp);

        emit EKRegistered(msg.sender, ek);
    }

    /// @notice User rotates EK (must be called by user wallet).
    function rotateEK(address newEk) external validEK(newEk) {
        EKRecord storage r = records[msg.sender];
        require(!r.revoked, "revoked");
        require(r.ek != address(0), "no EK");

        address old = r.ek;
        r.ek = newEk;
        r.updatedAt = uint64(block.timestamp);

        emit EKRotated(msg.sender, old, newEk);
    }

    /// @notice User revokes EK.
    function revokeEK() external {
        EKRecord storage r = records[msg.sender];
        require(r.ek != address(0), "no EK");
        require(!r.revoked, "already revoked");

        r.revoked = true;
        r.updatedAt = uint64(block.timestamp);

        emit EKRevoked(msg.sender, r.ek);
    }

    /// @notice View EK record for a user.
    function getEK(address user)
        external
        view
        returns (address ek, bool revoked, uint64 createdAt, uint64 updatedAt)
    {
        EKRecord storage r = records[user];
        return (r.ek, r.revoked, r.createdAt, r.updatedAt);
    }

    /// @notice Verify a signed message by the registered EK with nonce.
    /// @dev `messageHash` should already be a keccak256 of the message.
    function verifySignedByEK(
        address user,
        bytes32 messageHash,
        bytes calldata signature
    ) external returns (bool) {
        EKRecord storage r = records[user];
        require(!r.revoked, "revoked");
        require(r.ek != address(0), "no EK");

        uint256 userNonce = nonces[user];

        // Bind hash + nonce to prevent replay
        bytes32 fullHash = keccak256(abi.encodePacked(user, messageHash, userNonce));

        address signer = _recoverEthSignedMessage(fullHash, signature);
        require(signer == r.ek, "invalid EK signature");

        // Consume nonce
        nonces[user] = userNonce + 1;

        emit MessageVerified(user, signer, userNonce);
        return true;
    }

    /* ------------- INTERNAL ECDSA HELPERS ------------- */

    // Builds the Ethereum signed message:
    // keccak256("\x19Ethereum Signed Message:\n32" || hash)
    function _toEthSignedMessage(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );
    }

    function _recoverEthSignedMessage(bytes32 hash, bytes calldata sig)
        internal
        pure
        returns (address)
    {
        bytes32 ethHash = _toEthSignedMessage(hash);
        return _recover(ethHash, sig);
    }

    function _recover(bytes32 hash, bytes calldata sig)
        internal
        pure
        returns (address)
    {
        require(sig.length == 65, "sig len");

        bytes32 r;
        bytes32 s;
        uint8 v;

        // sig layout: r(32) | s(32) | v(1)
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }

        require(v == 27 || v == 28, "bad v");
        address recovered = ecrecover(hash, v, r, s);
        require(recovered != address(0), "ecrecover zero");
        return recovered;
    }
}
