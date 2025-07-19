// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Deep Packet Inspection (DPI) Demo
 * @notice A stubbed on-chain DPI system:
 *   • ADMIN_ROLE can add/remove signature patterns.
 *   • INSPECTOR_ROLE can submit packets for inspection.
 *   • The contract scans payloads for registered patterns and logs results.
 */
contract DeepPacketInspection {
    bytes32 public constant ADMIN_ROLE      = keccak256("ADMIN_ROLE");
    bytes32 public constant INSPECTOR_ROLE = keccak256("INSPECTOR_ROLE");

    // role → account → granted?
    mapping(bytes32 => mapping(address => bool)) private _roles;

    struct Signature {
        string name;
        bytes pattern;
        bool exists;
    }

    // signatureId → Signature
    mapping(uint256 => Signature) public signatures;
    uint256[] public signatureIds;
    mapping(uint256 => uint256) private _signatureIndex; // signatureId → index in signatureIds

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    event SignatureAdded(uint256 indexed id, string name, bytes pattern);
    event SignatureRemoved(uint256 indexed id);

    event PacketInspected(
        uint256 indexed packetId,
        address indexed inspector,
        address src,
        address dst,
        string protocol,
        bool matched,
        uint256 signatureId
    );

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "DPI: missing role");
        _;
    }

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /// @notice Grant a role to an account
    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }

    /// @notice Revoke a role from an account
    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _revokeRole(role, account);
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }

    /// @notice Add a new signature pattern
    function addSignature(uint256 id, string calldata name, bytes calldata pattern)
        external
        onlyRole(ADMIN_ROLE)
    {
        require(!signatures[id].exists, "DPI: signature exists");
        signatures[id] = Signature({ name: name, pattern: pattern, exists: true });
        signatureIds.push(id);
        _signatureIndex[id] = signatureIds.length - 1;
        emit SignatureAdded(id, name, pattern);
    }

    /// @notice Remove an existing signature
    function removeSignature(uint256 id) external onlyRole(ADMIN_ROLE) {
        require(signatures[id].exists, "DPI: unknown signature");
        // remove from array
        uint256 idx = _signatureIndex[id];
        uint256 lastId = signatureIds[signatureIds.length - 1];
        signatureIds[idx] = lastId;
        _signatureIndex[lastId] = idx;
        signatureIds.pop();
        delete _signatureIndex[id];

        delete signatures[id];
        emit SignatureRemoved(id);
    }

    /**
     * @notice Inspect a packet payload against registered signatures.
     * @param packetId Unique packet identifier.
     * @param src       Source address.
     * @param dst       Destination address.
     * @param protocol  Protocol name (e.g. "HTTP", "DNS").
     * @param payload   Full packet payload.
     * @return matched  Whether any signature matched.
     * @return sigId    The matching signature ID (or zero if none).
     */
    function inspectPacket(
        uint256 packetId,
        address src,
        address dst,
        string calldata protocol,
        bytes calldata payload
    )
        external
        onlyRole(INSPECTOR_ROLE)
        returns (bool matched, uint256 sigId)
    {
        // scan for each signature
        for (uint256 i = 0; i < signatureIds.length; i++) {
            uint256 id = signatureIds[i];
            bytes storage pattern = signatures[id].pattern;
            if (_contains(payload, pattern)) {
                emit PacketInspected(packetId, msg.sender, src, dst, protocol, true, id);
                return (true, id);
            }
        }
        emit PacketInspected(packetId, msg.sender, src, dst, protocol, false, 0);
        return (false, 0);
    }

    /// @dev Naïve in-memory substring search
    function _contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        uint256 h = haystack.length;
        uint256 n = needle.length;
        if (n == 0 || h < n) return false;
        for (uint256 i = 0; i <= h - n; i++) {
            bool ok = true;
            for (uint256 j = 0; j < n; j++) {
                if (haystack[i + j] != needle[j]) {
                    ok = false;
                    break;
                }
            }
            if (ok) return true;
        }
        return false;
    }
}
