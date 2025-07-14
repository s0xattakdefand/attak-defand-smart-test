// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DECENTRALIZED AUTONOMIC DATA MANAGER
 * — Implements a self-managing (autonomic) metadata registry for decentralized data.
 * — Roles: ADMIN_ROLE manages data items and replication policies;
 *          NODE_ROLE represents autonomous nodes hosting data.
 * — Nodes heartbeat to signal availability; contract suggests rebalance when nodes go stale.
 * — Full audit via events.
 */

abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }
    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not owner");
        _;
    }
    function owner() public view returns (address) {
        return _owner;
    }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant NODE_ROLE  = keccak256("NODE_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }
    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
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
}

contract DecentralizedAutonomicData is RBAC {
    struct DataItem {
        bytes32 pointer;            // off-chain data reference (e.g. IPFS CID)
        uint16  replicationFactor;  // desired number of replicas
        address[] nodes;            // assigned nodes
        bool    exists;
    }

    // node → dataId → last heartbeat timestamp
    mapping(address => mapping(uint256 => uint256)) private _heartbeats;
    mapping(uint256 => DataItem) public dataItems;
    uint256 public nextDataId;

    // Events
    event DataItemRegistered(uint256 indexed dataId, bytes32 pointer, uint16 replicationFactor);
    event NodeRegistered(address indexed node);
    event NodeAssigned(uint256 indexed dataId, address indexed node);
    event NodeRevoked(uint256 indexed dataId, address indexed node);
    event Heartbeat(uint256 indexed dataId, address indexed node, uint256 timestamp);
    event RebalanceSuggested(uint256 indexed dataId, address indexed staleNode, address indexed trigger);

    /// @notice ADMIN registers a new data item
    function registerDataItem(bytes32 pointer, uint16 replicationFactor)
        external
        onlyRole(ADMIN_ROLE)
        returns (uint256 dataId)
    {
        require(replicationFactor > 0, "Replication factor must be >0");
        dataId = nextDataId++;
        DataItem storage d = dataItems[dataId];
        d.pointer = pointer;
        d.replicationFactor = replicationFactor;
        d.exists = true;
        emit DataItemRegistered(dataId, pointer, replicationFactor);
    }

    /// @notice NODE_ROLE registers itself as host for a data item
    function assignNode(uint256 dataId) external onlyRole(NODE_ROLE) {
        DataItem storage d = dataItems[dataId];
        require(d.exists, "Unknown data item");
        require(!_isAssigned(d, msg.sender), "Node already assigned");
        d.nodes.push(msg.sender);
        _heartbeats[msg.sender][dataId] = block.timestamp;
        emit NodeAssigned(dataId, msg.sender);
    }

    /// @notice ADMIN can revoke a node from hosting a data item
    function revokeNode(uint256 dataId, address node) external onlyRole(ADMIN_ROLE) {
        DataItem storage d = dataItems[dataId];
        require(d.exists, "Unknown data item");
        uint256 len = d.nodes.length;
        for (uint i = 0; i < len; i++) {
            if (d.nodes[i] == node) {
                d.nodes[i] = d.nodes[len - 1];
                d.nodes.pop();
                delete _heartbeats[node][dataId];
                emit NodeRevoked(dataId, node);
                return;
            }
        }
        revert("Node not assigned");
    }

    /// @notice NODE_ROLE signals it is alive for a specific data item
    function heartbeat(uint256 dataId) external onlyRole(NODE_ROLE) {
        DataItem storage d = dataItems[dataId];
        require(d.exists && _isAssigned(d, msg.sender), "Not assigned");
        _heartbeats[msg.sender][dataId] = block.timestamp;
        emit Heartbeat(dataId, msg.sender, block.timestamp);
    }

    /// @notice Suggest rebalance if any node's heartbeat is stale
    /// @param dataId   Data item to check
    /// @param timeout  Seconds since last heartbeat to consider a node stale
    function suggestRebalance(uint256 dataId, uint256 timeout) external {
        DataItem storage d = dataItems[dataId];
        require(d.exists, "Unknown data item");
        uint256 nowTs = block.timestamp;
        for (uint i = 0; i < d.nodes.length; i++) {
            address node = d.nodes[i];
            uint256 last = _heartbeats[node][dataId];
            if (last == 0 || nowTs > last + timeout) {
                emit RebalanceSuggested(dataId, node, msg.sender);
            }
        }
    }

    /// @notice View assigned nodes for a data item
    function getAssignedNodes(uint256 dataId) external view returns (address[] memory) {
        return dataItems[dataId].nodes;
    }

    function _isAssigned(DataItem storage d, address node) private view returns (bool) {
        for (uint i = 0; i < d.nodes.length; i++) {
            if (d.nodes[i] == node) {
                return true;
            }
        }
        return false;
    }
}
