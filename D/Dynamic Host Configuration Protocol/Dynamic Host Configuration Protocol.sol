// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DynamicHostConfigurationProtocolAttackDefense - Full Attack and Defense Simulation for Dynamic Host Configuration Protocol (DHCP) in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Secure Dynamic Host Configuration Registry with Client Binding and Lease Validation
contract SecureDynamicHostConfiguration {
    address public owner;
    uint256 public leaseDuration = 1 days;
    uint256 public maxActiveLeasesPerClient = 1;

    struct LeaseInfo {
        address client;
        address assignedAddress;
        uint256 leaseExpiry;
    }

    mapping(bytes32 => LeaseInfo) public leases;
    mapping(address => uint256) public clientActiveLeases;
    mapping(address => bool) public registeredClients;

    event LeaseAssigned(bytes32 indexed leaseId, address indexed client, address assignedAddress, uint256 leaseExpiry);
    event LeaseRenewed(bytes32 indexed leaseId, address indexed client, uint256 leaseExpiry);
    event ClientRegistered(address indexed client);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerClient(address client) external onlyOwner {
        registeredClients[client] = true;
        emit ClientRegistered(client);
    }

    function assignLease(bytes32 leaseId, address client, address assignedAddress) external onlyOwner {
        require(registeredClients[client], "Unregistered client");
        require(clientActiveLeases[client] < maxActiveLeasesPerClient, "Lease limit reached");

        leases[leaseId] = LeaseInfo({
            client: client,
            assignedAddress: assignedAddress,
            leaseExpiry: block.timestamp + leaseDuration
        });

        clientActiveLeases[client] += 1;
        emit LeaseAssigned(leaseId, client, assignedAddress, block.timestamp + leaseDuration);
    }

    function renewLease(bytes32 leaseId) external {
        LeaseInfo storage lease = leases[leaseId];
        require(lease.client == msg.sender, "Not lease owner");
        require(block.timestamp <= lease.leaseExpiry, "Lease expired");

        lease.leaseExpiry = block.timestamp + leaseDuration;
        emit LeaseRenewed(leaseId, msg.sender, lease.leaseExpiry);
    }

    function getLeaseInfo(bytes32 leaseId) external view returns (address client, address assignedAddress, uint256 leaseExpiry) {
        LeaseInfo memory lease = leases[leaseId];
        return (lease.client, lease.assignedAddress, lease.leaseExpiry);
    }

    function expireLease(bytes32 leaseId) external onlyOwner {
        LeaseInfo storage lease = leases[leaseId];
        require(lease.client != address(0), "Invalid lease");

        clientActiveLeases[lease.client] -= 1;
        delete leases[leaseId];
    }
}

/// @notice Attack contract simulating DHCP-like attacks
contract DHCPIntruder {
    address public targetRegistry;

    constructor(address _targetRegistry) {
        targetRegistry = _targetRegistry;
    }

    function tryFakeAssign(bytes32 leaseId, address fakeClient, address fakeService) external returns (bool success) {
        (success, ) = targetRegistry.call(
            abi.encodeWithSignature("assignLease(bytes32,address,address)", leaseId, fakeClient, fakeService)
        );
    }
}
