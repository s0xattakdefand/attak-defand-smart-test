// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DISTRIBUTED COMPUTING ENVIRONMENT (DCE) DEMO
 * — A simple on-chain directory & invocation system for DCE-style services.
 *   Shows a vulnerable version with no controls, and a secure version with
 *   role-based registration, management, and invocation permissions.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDCE
   • Anyone can register any node or service.
   • No access control ⇒ no trust or audit.
----------------------------------------------------------------------------*/
contract VulnerableDCE {
    // Node metadata
    mapping(address => string) public nodeInfo;
    // Node → list of advertised services
    mapping(address => bytes32[]) public services;

    event NodeRegistered(address indexed node, string info);
    event ServiceAdvertised(address indexed node, bytes32 indexed serviceName);

    /// Anyone may register themselves as a node with arbitrary info.
    function registerNode(string calldata info) external {
        nodeInfo[msg.sender] = info;
        emit NodeRegistered(msg.sender, info);
    }

    /// Any node may advertise any service name.
    function advertiseService(bytes32 serviceName) external {
        services[msg.sender].push(serviceName);
        emit ServiceAdvertised(msg.sender, serviceName);
    }

    /// Discover services by node.
    function getServices(address node) external view returns (bytes32[] memory) {
        return services[node];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers: Ownable
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address public owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), owner);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureDCE
   • ADMIN registers nodes and assigns node managers.
   • Node managers register services and authorize clients.
   • Clients may invoke only authorized services.
   • Full audit via events.
----------------------------------------------------------------------------*/
contract SecureDCE is Ownable {
    // Node metadata
    mapping(address => string) public nodeInfo;
    // Node → manager address
    mapping(address => address) public nodeManager;
    // Node → serviceName → exists?
    mapping(address => mapping(bytes32 => bool)) public serviceExists;
    // Node → serviceName → list of service names
    mapping(address => bytes32[]) public servicesList;
    // Node → serviceName → client → authorized?
    mapping(address => mapping(bytes32 => mapping(address => bool))) public clientAuthorized;

    event NodeRegistered(address indexed node, string info);
    event NodeManagerAssigned(address indexed node, address indexed manager);
    event ServiceRegistered(address indexed node, bytes32 indexed serviceName);
    event ClientAuthorized(address indexed node, bytes32 indexed serviceName, address indexed client);
    event ServiceInvoked(address indexed node, bytes32 indexed serviceName, address indexed client, bytes payload);

    modifier onlyNodeManager(address node) {
        require(msg.sender == nodeManager[node], "Only node manager");
        _;
    }

    /// ADMIN registers a new node with metadata.
    function registerNode(address node, string calldata info) external onlyOwner {
        require(bytes(nodeInfo[node]).length == 0, "Node already registered");
        nodeInfo[node] = info;
        emit NodeRegistered(node, info);
    }

    /// ADMIN assigns a manager for a node.
    function assignNodeManager(address node, address manager) external onlyOwner {
        require(bytes(nodeInfo[node]).length != 0, "Unknown node");
        nodeManager[node] = manager;
        emit NodeManagerAssigned(node, manager);
    }

    /// Node manager registers a service name under their node.
    function registerService(bytes32 serviceName) external {
        address node = msg.sender;
        // require you are manager of some node; for simplicity manager==node
        require(nodeManager[node] == node, "Must be your own node");
        require(!serviceExists[node][serviceName], "Service exists");
        serviceExists[node][serviceName] = true;
        servicesList[node].push(serviceName);
        emit ServiceRegistered(node, serviceName);
    }

    /// Node manager authorizes a client to invoke a named service.
    function authorizeClient(bytes32 serviceName, address client) external {
        address node = msg.sender;
        require(nodeManager[node] == node, "Only node manager");
        require(serviceExists[node][serviceName], "Unknown service");
        clientAuthorized[node][serviceName][client] = true;
        emit ClientAuthorized(node, serviceName, client);
    }

    /// Client invokes a service on a node with arbitrary payload.
    function invokeService(address node, bytes32 serviceName, bytes calldata payload) external {
        require(serviceExists[node][serviceName], "Unknown service");
        require(clientAuthorized[node][serviceName][msg.sender], "Not authorized");
        emit ServiceInvoked(node, serviceName, msg.sender, payload);
        // Off-chain or other on-chain logic could be triggered by this event...
    }

    /// Discover services by node.
    function getServices(address node) external view returns (bytes32[] memory) {
        return servicesList[node];
    }

    /// Check if a client is authorized for a service.
    function isAuthorized(address node, bytes32 serviceName, address client) external view returns (bool) {
        return clientAuthorized[node][serviceName][client];
    }
}
