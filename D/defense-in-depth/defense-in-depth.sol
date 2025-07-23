// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DefenseInDepthStrategy
 * @notice Implements an information security strategy (“Defense-in-Depth”) by modeling
 *         multiple layers (people, technology, operations) with per-layer role-based
 *         management of barriers/controls and full audit logging.
 * Sources:
 *   • CNSSI 4009-2015
 *   • NIST SP 800-172 & 800-172A
 *   • NIST SP 800-30 Rev.1 & 800-39 under Defense-in-Depth
 */
contract DefenseInDepthStrategy {
    struct Barrier {
        uint256    id;
        string     description;
        string     controlType;  // e.g. "Technical", "Administrative", "Physical"
        address    createdBy;
        uint256    createdAt;
        bool       active;
    }

    struct Layer {
        bool                    exists;
        address                 admin;
        mapping(address => bool) managers;
        mapping(address => bool) viewers;
        uint256                 nextBarrierId;
        mapping(uint256 => Barrier) barriers;
    }

    mapping(string => Layer) private _layers;

    // Global admin
    address public owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    event LayerCreated(string indexed layer, address indexed admin);
    event LayerAdminTransferred(string indexed layer, address indexed oldAdmin, address indexed newAdmin);
    event ManagerGranted(string indexed layer, address indexed account);
    event ManagerRevoked(string indexed layer, address indexed account);
    event ViewerGranted(string indexed layer, address indexed account);
    event ViewerRevoked(string indexed layer, address indexed account);

    event BarrierAdded(
        string indexed layer,
        uint256 indexed barrierId,
        string description,
        string controlType,
        address indexed createdBy,
        uint256 timestamp
    );
    event BarrierUpdated(
        string indexed layer,
        uint256 indexed barrierId,
        string description,
        string controlType,
        bool active,
        address indexed updatedBy,
        uint256 timestamp
    );
    event BarrierRemoved(string indexed layer, uint256 indexed barrierId, address indexed removedBy, uint256 timestamp);
    event BarrierViewed(string indexed layer, uint256 indexed barrierId, address indexed viewer, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not contract owner");
        _;
    }

    modifier onlyLayerAdmin(string calldata layer) {
        require(_layers[layer].exists, "Layer not found");
        require(_layers[layer].admin == msg.sender, "Not layer admin");
        _;
    }

    modifier onlyManager(string calldata layer) {
        require(_layers[layer].exists, "Layer not found");
        require(_layers[layer].managers[msg.sender], "Not layer manager");
        _;
    }

    modifier onlyViewer(string calldata layer) {
        require(_layers[layer].exists, "Layer not found");
        require(
            _layers[layer].viewers[msg.sender] || _layers[layer].managers[msg.sender],
            "Not layer viewer"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Transfer contract ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Create a new defense-in-depth layer (e.g. "People", "Technology", "Operations")
    function createLayer(string calldata layer) external {
        Layer storage l = _layers[layer];
        require(!l.exists, "Layer exists");
        l.exists = true;
        l.admin = msg.sender;
        l.managers[msg.sender] = true;
        l.viewers[msg.sender] = true;
        emit LayerCreated(layer, msg.sender);
    }

    /// @notice Transfer administrative control of a layer
    function transferLayerAdmin(string calldata layer, address newAdmin)
        external
        onlyLayerAdmin(layer)
    {
        require(newAdmin != address(0), "Zero address");
        Layer storage l = _layers[layer];
        address old = l.admin;
        l.admin = newAdmin;
        l.managers[newAdmin] = true;
        l.viewers[newAdmin] = true;
        emit LayerAdminTransferred(layer, old, newAdmin);
    }

    /// @notice Grant or revoke manager role for a layer
    function grantManager(string calldata layer, address account) external onlyLayerAdmin(layer) {
        _layers[layer].managers[account] = true;
        emit ManagerGranted(layer, account);
    }
    function revokeManager(string calldata layer, address account) external onlyLayerAdmin(layer) {
        _layers[layer].managers[account] = false;
        emit ManagerRevoked(layer, account);
    }

    /// @notice Grant or revoke viewer role for a layer
    function grantViewer(string calldata layer, address account) external onlyLayerAdmin(layer) {
        _layers[layer].viewers[account] = true;
        emit ViewerGranted(layer, account);
    }
    function revokeViewer(string calldata layer, address account) external onlyLayerAdmin(layer) {
        _layers[layer].viewers[account] = false;
        emit ViewerRevoked(layer, account);
    }

    /// @notice Add a new barrier/control to a layer
    function addBarrier(
        string calldata layer,
        string calldata description,
        string calldata controlType
    )
        external
        onlyManager(layer)
        returns (uint256 barrierId)
    {
        Layer storage l = _layers[layer];
        barrierId = l.nextBarrierId++;
        l.barriers[barrierId] = Barrier({
            id:          barrierId,
            description: description,
            controlType: controlType,
            createdBy:   msg.sender,
            createdAt:   block.timestamp,
            active:      true
        });
        emit BarrierAdded(layer, barrierId, description, controlType, msg.sender, block.timestamp);
    }

    /// @notice Update an existing barrier
    function updateBarrier(
        string calldata layer,
        uint256 barrierId,
        string calldata description,
        string calldata controlType,
        bool active
    )
        external
        onlyManager(layer)
    {
        Layer storage l = _layers[layer];
        Barrier storage b = l.barriers[barrierId];
        require(b.createdAt != 0, "Barrier not found");
        b.description = description;
        b.controlType = controlType;
        b.active = active;
        emit BarrierUpdated(
            layer, barrierId, description, controlType, active, msg.sender, block.timestamp
        );
    }

    /// @notice Remove (deactivate) a barrier
    function removeBarrier(string calldata layer, uint256 barrierId) external onlyManager(layer) {
        Layer storage l = _layers[layer];
        Barrier storage b = l.barriers[barrierId];
        require(b.createdAt != 0, "Barrier not found");
        b.active = false;
        emit BarrierRemoved(layer, barrierId, msg.sender, block.timestamp);
    }

    /// @notice View a barrier’s details (with audit)
    function viewBarrier(string calldata layer, uint256 barrierId)
        external
        onlyViewer(layer)
        returns (
            string memory description,
            string memory controlType,
            address createdBy,
            uint256 createdAt,
            bool active
        )
    {
        Layer storage l = _layers[layer];
        Barrier storage b = l.barriers[barrierId];
        require(b.createdAt != 0, "Barrier not found");
        emit BarrierViewed(layer, barrierId, msg.sender, block.timestamp);
        return (b.description, b.controlType, b.createdBy, b.createdAt, b.active);
    }

    /// @notice Get the number of barriers in a layer
    function barrierCount(string calldata layer) external view returns (uint256) {
        return _layers[layer].nextBarrierId;
    }
}
