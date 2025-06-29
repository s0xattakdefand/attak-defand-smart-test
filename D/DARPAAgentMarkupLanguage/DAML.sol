// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DARPA Agent Markup Language (AGML) Registry
 * @notice
 *   On‐chain registry for DARPA Agent Markup Language documents.
 *   • Agents are registered by “CREATOR_ROLE” accounts.
 *   • Each agent document may be versioned; updates emit events.
 *   • Anyone can read published AGML definitions.
 *   • Admins may pause publishing in emergencies.
 */
contract AGMLRegistry is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE   = keccak256("ADMIN_ROLE");
    bytes32 public constant CREATOR_ROLE = keccak256("CREATOR_ROLE");

    struct AgentDefinition {
        address creator;
        string  uri;        // IPFS / HTTPS pointer to AGML XML
        uint256 version;
        bool    exists;
    }

    // agentId → version → definition
    mapping(bytes32 => mapping(uint256 => AgentDefinition)) private _definitions;
    // agentId → latest version number
    mapping(bytes32 => uint256) private _latestVersion;

    event AgentRegistered(bytes32 indexed agentId, address indexed creator, uint256 version, string uri);
    event AgentUpdated   (bytes32 indexed agentId, address indexed creator, uint256 version, string uri);
    event AgentDeleted   (bytes32 indexed agentId, uint256 version);

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "AGML: not admin");
        _;
    }

    modifier onlyCreator(bytes32 agentId) {
        require(
            _definitions[agentId][_latestVersion[agentId]].creator == msg.sender,
            "AGML: not creator"
        );
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    /// @notice Grant CREATOR_ROLE to an account
    function grantCreator(address account) external onlyAdmin {
        grantRole(CREATOR_ROLE, account);
    }

    /// @notice Revoke CREATOR_ROLE from an account
    function revokeCreator(address account) external onlyAdmin {
        revokeRole(CREATOR_ROLE, account);
    }

    /// @notice Register a new agent definition (initial version = 1)
    /// @param agentId  Unique identifier for the agent (e.g. keccak256 of name)
    /// @param uri      URI pointing to the AGML XML document
    function registerAgent(bytes32 agentId, string calldata uri)
        external
        whenNotPaused
        onlyRole(CREATOR_ROLE)
    {
        require(!_definitions[agentId][1].exists, "AGML: already registered");
        _definitions[agentId][1] = AgentDefinition({
            creator: msg.sender,
            uri:     uri,
            version: 1,
            exists:  true
        });
        _latestVersion[agentId] = 1;
        emit AgentRegistered(agentId, msg.sender, 1, uri);
    }

    /// @notice Update an existing agent definition (bump version)
    function updateAgent(bytes32 agentId, string calldata uri)
        external
        whenNotPaused
        onlyRole(CREATOR_ROLE)
        onlyCreator(agentId)
    {
        uint256 nextVer = _latestVersion[agentId] + 1;
        _definitions[agentId][nextVer] = AgentDefinition({
            creator: msg.sender,
            uri:     uri,
            version: nextVer,
            exists:  true
        });
        _latestVersion[agentId] = nextVer;
        emit AgentUpdated(agentId, msg.sender, nextVer, uri);
    }

    /// @notice Delete a specific version of an agent definition
    function deleteAgentVersion(bytes32 agentId, uint256 version)
        external
        whenNotPaused
        onlyRole(ADMIN_ROLE)
    {
        require(_definitions[agentId][version].exists, "AGML: version not exist");
        delete _definitions[agentId][version];
        // if deleting latest, roll back latestVersion
        if (_latestVersion[agentId] == version) {
            _latestVersion[agentId] = version > 1 ? version - 1 : 0;
        }
        emit AgentDeleted(agentId, version);
    }

    /// @notice Fetch the latest AGML URI and version for an agent
    function getLatestAgent(bytes32 agentId)
        external
        view
        returns (string memory uri, uint256 version, address creator)
    {
        uint256 v = _latestVersion[agentId];
        require(v != 0, "AGML: not registered");
        AgentDefinition storage def = _definitions[agentId][v];
        return (def.uri, v, def.creator);
    }

    /// @notice Fetch a specific version of an agent definition
    function getAgentVersion(bytes32 agentId, uint256 version)
        external
        view
        returns (string memory uri, address creator)
    {
        AgentDefinition storage def = _definitions[agentId][version];
        require(def.exists, "AGML: version not exist");
        return (def.uri, def.creator);
    }

    /// @notice Pause registry actions
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause registry actions
    function unpause() external onlyAdmin {
        _unpause();
    }
}
