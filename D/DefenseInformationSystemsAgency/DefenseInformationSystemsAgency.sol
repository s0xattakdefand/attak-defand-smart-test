// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DISAServiceRegistry
 * @notice Registry for Defense Information Systems Agency (DISA) services/assets,
 *         with per-category granularity, role-based access, and full audit logging.
 */
contract DISAServiceRegistry {
    enum Classification { Unclassified, Confidential, Secret, TopSecret }

    // Role identifiers
    bytes32 public constant ADMIN_ROLE    = keccak256("ADMIN_ROLE");
    bytes32 public constant MANAGER_ROLE  = keccak256("MANAGER_ROLE");
    bytes32 public constant VIEWER_ROLE   = keccak256("VIEWER_ROLE");

    // role => account => granted?
    mapping(bytes32 => mapping(address => bool)) private _roles;

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "DISA: missing role");
        _;
    }

    constructor() {
        // deployer is initial ADMIN
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _grantRole(role, account);
    }
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

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    struct Service {
        uint256          id;
        string           name;
        string           endpoint;
        string           description;
        Classification   classification;
        address          addedBy;
        uint256          addedAt;
        bool             exists;
    }

    struct Category {
        bool             exists;
        address          admin;
        mapping(address => bool) managers;
        mapping(address => bool) viewers;
        uint256          nextServiceId;
        mapping(uint256 => Service) services;
    }

    mapping(string => Category) private _categories;
    string[] public categories;

    event CategoryCreated(string indexed category, address indexed admin);
    event ManagerGranted(string indexed category, address indexed account);
    event ManagerRevoked(string indexed category, address indexed account);
    event ViewerGranted(string indexed category, address indexed account);
    event ViewerRevoked(string indexed category, address indexed account);

    event ServiceAdded(
        string indexed category,
        uint256 indexed serviceId,
        string name,
        string endpoint,
        Classification classification,
        address indexed addedBy,
        uint256 timestamp
    );
    event ServiceUpdated(
        string indexed category,
        uint256 indexed serviceId,
        string name,
        string endpoint,
        address indexed updatedBy,
        uint256 timestamp
    );
    event ServiceRemoved(string indexed category, uint256 indexed serviceId, address indexed removedBy);
    event ServiceRead(
        string indexed category,
        uint256 indexed serviceId,
        address indexed reader,
        uint256 timestamp
    );

    /// @notice Create a new category of DISA services
    function createCategory(string calldata category) external onlyRole(ADMIN_ROLE) {
        Category storage c = _categories[category];
        require(!c.exists, "DISA: category exists");
        c.exists = true;
        c.admin = msg.sender;
        categories.push(category);
        emit CategoryCreated(category, msg.sender);
    }

    function grantManager(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISA: unknown category");
        require(msg.sender == c.admin, "DISA: only category admin");
        c.managers[account] = true;
        emit ManagerGranted(category, account);
    }

    function revokeManager(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISA: unknown category");
        require(msg.sender == c.admin, "DISA: only category admin");
        c.managers[account] = false;
        emit ManagerRevoked(category, account);
    }

    function grantViewer(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISA: unknown category");
        require(msg.sender == c.admin, "DISA: only category admin");
        c.viewers[account] = true;
        emit ViewerGranted(category, account);
    }

    function revokeViewer(string calldata category, address account) external {
        Category storage c = _categories[category];
        require(c.exists, "DISA: unknown category");
        require(msg.sender == c.admin, "DISA: only category admin");
        c.viewers[account] = false;
        emit ViewerRevoked(category, account);
    }

    modifier onlyManager(string calldata category) {
        Category storage c = _categories[category];
        require(c.exists, "DISA: unknown category");
        require(c.managers[msg.sender], "DISA: not a manager");
        _;
    }
    modifier onlyViewer(string calldata category) {
        Category storage c = _categories[category];
        require(c.exists, "DISA: unknown category");
        require(c.viewers[msg.sender] || c.managers[msg.sender], "DISA: not a viewer");
        _;
    }

    /// @notice Add a new service asset under a category
    function addService(
        string calldata category,
        string calldata name,
        string calldata endpoint,
        string calldata description,
        Classification classification
    )
        external
        onlyManager(category)
        returns (uint256 serviceId)
    {
        Category storage c = _categories[category];
        serviceId = c.nextServiceId++;
        c.services[serviceId] = Service({
            id:             serviceId,
            name:           name,
            endpoint:       endpoint,
            description:    description,
            classification: classification,
            addedBy:        msg.sender,
            addedAt:        block.timestamp,
            exists:         true
        });
        emit ServiceAdded(category, serviceId, name, endpoint, classification, msg.sender, block.timestamp);
    }

    /// @notice Update an existing service asset
    function updateService(
        string calldata category,
        uint256 serviceId,
        string calldata name,
        string calldata endpoint,
        string calldata description
    )
        external
        onlyManager(category)
    {
        Service storage s = _categories[category].services[serviceId];
        require(s.exists, "DISA: service not found");
        s.name        = name;
        s.endpoint    = endpoint;
        s.description = description;
        s.addedBy     = msg.sender;
        s.addedAt     = block.timestamp;
        emit ServiceUpdated(category, serviceId, name, endpoint, msg.sender, block.timestamp);
    }

    /// @notice Remove a service asset (soft delete)
    function removeService(string calldata category, uint256 serviceId) external onlyManager(category) {
        Service storage s = _categories[category].services[serviceId];
        require(s.exists, "DISA: service not found");
        delete _categories[category].services[serviceId];
        emit ServiceRemoved(category, serviceId, msg.sender);
    }

    /// @notice Read a service asset’s details
    function readService(string calldata category, uint256 serviceId)
        external
        onlyViewer(category)
        returns (
            string memory name,
            string memory endpoint,
            string memory description,
            Classification classification,
            address addedBy,
            uint256 addedAt
        )
    {
        Service storage s = _categories[category].services[serviceId];
        require(s.exists, "DISA: service not found");
        emit ServiceRead(category, serviceId, msg.sender, block.timestamp);
        return (s.name, s.endpoint, s.description, s.classification, s.addedBy, s.addedAt);
    }
}
