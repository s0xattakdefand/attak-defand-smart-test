// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonServiceProviderRegistry {
    address public admin;

    struct Service {
        string serviceType;            // e.g. "Oracle", "AccessControl", "ZKVerifier"
        bytes4 interfaceId;           // ERC165 interface ID or custom identifier
        bool active;
        uint256 registeredAt;
    }

    mapping(address => Service) public providers;
    address[] public providerList;

    event ProviderRegistered(address indexed provider, string serviceType, bytes4 interfaceId);
    event ProviderStatusChanged(address indexed provider, bool active);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CSP: Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerProvider(address provider, string calldata serviceType, bytes4 interfaceId) external onlyAdmin {
        require(providers[provider].registeredAt == 0, "CSP: Already registered");

        providers[provider] = Service({
            serviceType: serviceType,
            interfaceId: interfaceId,
            active: true,
            registeredAt: block.timestamp
        });

        providerList.push(provider);
        emit ProviderRegistered(provider, serviceType, interfaceId);
    }

    function setProviderStatus(address provider, bool active) external onlyAdmin {
        require(providers[provider].registeredAt != 0, "CSP: Not found");
        providers[provider].active = active;
        emit ProviderStatusChanged(provider, active);
    }

    function isActive(address provider) external view returns (bool) {
        return providers[provider].active;
    }

    function getProvider(address provider) external view returns (
        string memory serviceType,
        bytes4 interfaceId,
        bool active,
        uint256 registeredAt
    ) {
        Service memory s = providers[provider];
        return (s.serviceType, s.interfaceId, s.active, s.registeredAt);
    }

    function getAllProviders() external view returns (address[] memory) {
        return providerList;
    }
}
