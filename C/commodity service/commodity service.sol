// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommodityServiceRegistry {
    address public admin;

    struct Service {
        string name;
        string endpoint;         // e.g., "https://rpc.service.org"
        uint256 feePerCall;      // in wei
        bool active;
        uint256 version;
    }

    mapping(address => Service) public services;
    address[] public serviceProviders;

    event ServiceRegistered(address indexed provider, string name, string endpoint);
    event ServiceUsed(address indexed user, address indexed provider, uint256 fee, string method);
    event ServiceUpdated(address indexed provider, string newEndpoint, uint256 newVersion);
    event ServiceStatusChanged(address indexed provider, bool active);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyRegisteredProvider() {
        require(services[msg.sender].version > 0, "Not registered");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Admin registers a commodity service provider
    function registerService(
        address provider,
        string calldata name,
        string calldata endpoint,
        uint256 feePerCall
    ) external onlyAdmin {
        require(bytes(name).length > 0, "Name required");
        require(bytes(endpoint).length > 0, "Endpoint required");
        require(services[provider].version == 0, "Already registered");

        services[provider] = Service(name, endpoint, feePerCall, true, 1);
        serviceProviders.push(provider);

        emit ServiceRegistered(provider, name, endpoint);
    }

    // Provider updates their endpoint or version
    function updateService(string calldata newEndpoint, uint256 newVersion) external onlyRegisteredProvider {
        Service storage s = services[msg.sender];
        s.endpoint = newEndpoint;
        s.version = newVersion;

        emit ServiceUpdated(msg.sender, newEndpoint, newVersion);
    }

    // Admin toggles service availability
    function setServiceActive(address provider, bool active) external onlyAdmin {
        require(services[provider].version > 0, "Not registered");
        services[provider].active = active;
        emit ServiceStatusChanged(provider, active);
    }

    // User simulates using a service (fee and metadata logging)
    function useService(address provider, string calldata methodName) external payable {
        Service memory s = services[provider];
        require(s.active, "Service inactive");
        require(msg.value >= s.feePerCall, "Insufficient fee");

        emit ServiceUsed(msg.sender, provider, s.feePerCall, methodName);
        payable(provider).transfer(s.feePerCall);

        // Optionally: return calldata result or simulate response via off-chain
    }

    // Public getter
    function getAllProviders() external view returns (address[] memory) {
        return serviceProviders;
    }
}
