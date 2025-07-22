// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DISNAssetRegistry
 * @notice Registry for Defense Information System Network (DISN) assets—
 *         Sites, Gateways, Services—with fine-grained per-category access control.
 *
 * Roles:
 *  • ADMIN_ROLE       – manage categories and role assignments
 *  • MANAGER_ROLE     – add/update/remove assets in a category
 *  • VIEWER_ROLE      – view assets in a category
 *
 * Classification domains: Unclassified, Secret, TopSecret.
 */
contract DISNAssetRegistry {
    // Classification levels for DISN assets
    enum Classification { Unclassified, Secret, TopSecret }

    // Role identifiers
    bytes32 public constant ADMIN_ROLE   = keccak256("ADMIN_ROLE");
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");
    bytes32 public constant VIEWER_ROLE  = keccak256("VIEWER_ROLE");

    // role => account => granted?
    mapping(bytes32 => mapping(address => bool)) private _roles;

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "DISN: missing required role");
        _;
    }

    constructor() {
        // Deployer is initial ADMIN
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /// @dev Internal: grant a role
    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    /// @dev Internal: revoke a role
    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }

    /*** Role management ***/

    /// @notice Grant a role to an account (only ADMIN)
    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }

    /// @notice Revoke a role from an account (only ADMIN)
    function revokeRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _revokeRole(role, account);
    }

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    /*** Category & Asset storage ***/

    struct Asset {
        uint256          id;
        string           name;
        string           location;
        string           details;
        Classification   classification;
        address          addedBy;
        uint256          timestamp;
        bool             exists;
    }

    struct Category {
        bool    exists;
        address admin;
        mapping(address => bool) managers;
        mapping(address => bool) viewers;
        uint256 nextAssetId;
        mapping(uint256 => Asset) assets;
    }

    // categoryName => Category
    mapping(string => Category) private _categories;
    string[] public categories;

    /*** Events ***/

    event CategoryCreated(string indexed category, address indexed admin);
    event ManagerGranted(string indexed category, address indexed account);
    event ManagerRevoked(string indexed category, address indexed account);
    event ViewerGranted(string indexed category, address indexed account);
    event ViewerRevoked(string indexed category, address indexed account);

    event AssetAdded(
        string indexed category,
        uint256 indexed assetId,
        string name,
        address indexed addedBy,
        Classification classification,
        uint256 timestamp
    );
    event AssetUpdated(
        string indexed category,
        uint256 indexed assetId,
        string name,
        address indexed updatedBy,
        uint256 timestamp
    );
    event AssetRemoved(string indexed category, uint256 indexed assetId, address indexed removedBy);
    event AssetRead(
        string indexed category,
        uint256 indexed assetId,
        address indexed reader,
        uint256 timestamp
    );

    /*** Category management ***/

    /// @notice Create a new asset category (e.g. "Site", "Gateway", "Service")
    function createCategory(string calldata category) external onlyRole(ADMIN_ROLE) {
        Category storage c = _categories[category];
        require(!c.exists, "DISN: category exists");
        c.exists = true;
        c.admin = msg.sender;
        categories.push(category);
        emit CategoryCreated(category, msg.sender);
    }

    /// @notice Grant manager rights for a category (only category admin)
    function grantManager(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISN: category not found");
        require(msg.sender == c.admin, "DISN: only category admin");
        c.managers[account] = true;
        emit ManagerGranted(category, account);
    }

    /// @notice Revoke manager rights for a category (only category admin)
    function revokeManager(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISN: category not found");
        require(msg.sender == c.admin, "DISN: only category admin");
        c.managers[account] = false;
        emit ManagerRevoked(category, account);
    }

    /// @notice Grant viewer rights for a category (only category admin)
    function grantViewer(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISN: category not found");
        require(msg.sender == c.admin, "DISN: only category admin");
        c.viewers[account] = true;
        emit ViewerGranted(category, account);
    }

    /// @notice Revoke viewer rights for a category (only category admin)
    function revokeViewer(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISN: category not found");
        require(msg.sender == c.admin, "DISN: only category admin");
        c.viewers[account] = false;
        emit ViewerRevoked(category, account);
    }

    /*** Asset management ***/

    modifier onlyManager(string calldata category) {
        Category storage c = _categories[category];
        require(c.exists, "DISN: category not found");
        require(c.managers[msg.sender], "DISN: not a manager");
        _;
    }
    modifier onlyViewer(string calldata category) {
        Category storage c = _categories[category];
        require(c.exists, "DISN: category not found");
        require(c.viewers[msg.sender] || c.managers[msg.sender], "DISN: not a viewer");
        _;
    }

    /// @notice Add a new asset under a category
    function addAsset(
        string calldata category,
        string calldata name,
        string calldata location,
        string calldata details,
        Classification classification
    )
        external
        onlyManager(category)
        returns (uint256 assetId)
    {
        Category storage c = _categories[category];
        assetId = c.nextAssetId++;
        c.assets[assetId] = Asset({
            id:             assetId,
            name:           name,
            location:       location,
            details:        details,
            classification: classification,
            addedBy:        msg.sender,
            timestamp:      block.timestamp,
            exists:         true
        });
        emit AssetAdded(category, assetId, name, msg.sender, classification, block.timestamp);
    }

    /// @notice Update an existing asset
    function updateAsset(
        string calldata category,
        uint256 assetId,
        string calldata name,
        string calldata location,
        string calldata details
    )
        external
        onlyManager(category)
    {
        Category storage c = _categories[category];
        Asset storage a = c.assets[assetId];
        require(a.exists, "DISN: asset not found");
        a.name      = name;
        a.location  = location;
        a.details   = details;
        a.addedBy   = msg.sender;
        a.timestamp = block.timestamp;
        emit AssetUpdated(category, assetId, name, msg.sender, block.timestamp);
    }

    /// @notice Remove an asset (soft delete)
    function removeAsset(string calldata category, uint256 assetId) external onlyManager(category) {
        Category storage c = _categories[category];
        Asset storage a = c.assets[assetId];
        require(a.exists, "DISN: asset not found");
        delete c.assets[assetId];
        emit AssetRemoved(category, assetId, msg.sender);
    }

    /// @notice Read an asset’s data
    function readAsset(string calldata category, uint256 assetId)
        external
        onlyViewer(category)
        returns (
            string memory name,
            string memory location,
            string memory details,
            Classification classification,
            address addedBy,
            uint256 timestamp
        )
    {
        Asset storage a = _categories[category].assets[assetId];
        require(a.exists, "DISN: asset not found");
        emit AssetRead(category, assetId, msg.sender, block.timestamp);
        return (a.name, a.location, a.details, a.classification, a.addedBy, a.timestamp);
    }
}
