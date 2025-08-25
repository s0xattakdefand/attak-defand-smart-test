// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Decentralized Name Service - Service Discovery (DNS-SD) smart contract
contract DNSSD {
    // Enum for service record types
    enum RecordType { SRV, TXT }

    // Struct to represent a service record
    struct ServiceRecord {
        RecordType recordType; // Type of record (SRV or TXT)
        bytes data; // SRV: encoded port and target; TXT: key-value pairs
        uint256 priority; // Priority for SRV records
        uint256 weight; // Weight for SRV records
    }

    // Struct to represent a service instance
    struct Service {
        string instanceName; // Service instance name (e.g., "_printer._tcp")
        mapping(string => ServiceRecord) records; // Record key to ServiceRecord
        string[] recordKeys; // List of record keys for iteration
    }

    // Struct to represent a domain
    struct Domain {
        address owner; // Owner of the domain
        uint256 registrationTime; // Timestamp of registration
        uint256 expiryTime; // Timestamp when domain expires
        mapping(string => Service) services; // Service type to Service mapping
        string[] serviceTypes; // List of service types for discovery
    }

    // Mapping to store domains
    mapping(string => Domain) public domains;

    // Owner of the contract
    address public owner;

    // Authorized resolvers for service queries
    mapping(address => bool) public resolvers;

    // Registration fee (in wei)
    uint256 public constant REGISTRATION_FEE = 0.01 ether;

    // Default registration duration (1 year in seconds)
    uint256 public constant REGISTRATION_DURATION = 365 days;

    // Event emitted when a domain is registered
    event DomainRegistered(string indexed domain, address owner, uint256 expiryTime);

    // Event emitted when a service is registered
    event ServiceRegistered(string indexed domain, string serviceType, string instanceName);

    // Event emitted when a service record is set
    event ServiceRecordSet(
        string indexed domain,
        string serviceType,
        string recordKey,
        RecordType recordType,
        bytes data,
        uint256 priority,
        uint256 weight
    );

    // Event emitted when a domain is renewed
    event DomainRenewed(string indexed domain, uint256 newExpiryTime);

    // Event emitted when a domain is transferred
    event DomainTransferred(string indexed domain, address newOwner);

    // Event emitted when a resolver is added or removed
    event ResolverUpdated(address indexed resolver, bool authorized);

    // Modifier to restrict actions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict actions to the domain owner
    modifier onlyDomainOwner(string memory domain) {
        require(domains[domain].owner == msg.sender, "Not the domain owner");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        _;
    }

    // Modifier to check if domain is available or expired
    modifier domainAvailable(string memory domain) {
        require(
            domains[domain].owner == address(0) || block.timestamp > domains[domain].expiryTime,
            "Domain is already registered and not expired"
        );
        _;
    }

    // Modifier to restrict actions to authorized resolvers or owner
    modifier onlyResolver() {
        require(resolvers[msg.sender] || msg.sender == owner, "Not an authorized resolver");
        _;
    }

    // Constructor to initialize the owner and set owner as initial resolver
    constructor() {
        owner = msg.sender;
        resolvers[msg.sender] = true;
        emit ResolverUpdated(msg.sender, true);
    }

    // Register a new domain
    function registerDomain(string memory domain) 
        external 
        payable 
        domainAvailable(domain) 
    {
        require(bytes(domain).length > 0, "Domain cannot be empty");
        require(msg.value >= REGISTRATION_FEE, "Insufficient registration fee");

        domains[domain].owner = msg.sender;
        domains[domain].registrationTime = block.timestamp;
        domains[domain].expiryTime = block.timestamp + REGISTRATION_DURATION;

        // Refund excess payment
        if (msg.value > REGISTRATION_FEE) {
            payable(msg.sender).transfer(msg.value - REGISTRATION_FEE);
        }

        emit DomainRegistered(domain, msg.sender, block.timestamp + REGISTRATION_DURATION);
    }

    // Renew an existing domain
    function renewDomain(string memory domain) 
        external 
        payable 
        onlyDomainOwner(domain) 
    {
        require(msg.value >= REGISTRATION_FEE, "Insufficient renewal fee");

        domains[domain].expiryTime += REGISTRATION_DURATION;

        // Refund excess payment
        if (msg.value > REGISTRATION_FEE) {
            payable(msg.sender).transfer(msg.value - REGISTRATION_FEE);
        }

        emit DomainRenewed(domain, domains[domain].expiryTime);
    }

    // Transfer domain ownership
    function transferDomain(string memory domain, address newOwner) 
        external 
        onlyDomainOwner(domain) 
    {
        require(newOwner != address(0), "Invalid new owner");

        domains[domain].owner = newOwner;
        emit DomainTransferred(domain, newOwner);
    }

    // Register a service under a domain
    function registerService(
        string memory domain,
        string memory serviceType,
        string memory instanceName
    ) 
        external 
        onlyDomainOwner(domain) 
    {
        require(bytes(serviceType).length > 0, "Service type cannot be empty");
        require(bytes(instanceName).length > 0, "Instance name cannot be empty");

        // Add service type to list if not already present
        bool exists = false;
        for (uint256 i = 0; i < domains[domain].serviceTypes.length; i++) {
            if (keccak256(abi.encodePacked(domains[domain].serviceTypes[i])) == keccak256(abi.encodePacked(serviceType))) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            domains[domain].serviceTypes.push(serviceType);
        }

        domains[domain].services[serviceType].instanceName = instanceName;
        emit ServiceRegistered(domain, serviceType, instanceName);
    }

    // Set a service record (SRV or TXT)
    function setServiceRecord(
        string memory domain,
        string memory serviceType,
        string memory recordKey,
        RecordType recordType,
        bytes memory data,
        uint256 priority,
        uint256 weight
    ) 
        external 
        onlyDomainOwner(domain) 
    {
        require(bytes(serviceType).length > 0, "Service type cannot be empty");
        require(bytes(recordKey).length > 0, "Record key cannot be empty");
        require(bytes(domains[domain].services[serviceType].instanceName).length > 0, "Service not registered");
        require(data.length > 0, "Record data cannot be empty");
        if (recordType == RecordType.SRV) {
            require(data.length >= 20, "SRV data must include target address");
        }

        // Add record key to list if not already present
        bool exists = false;
        for (uint256 i = 0; i < domains[domain].services[serviceType].recordKeys.length; i++) {
            if (keccak256(abi.encodePacked(domains[domain].services[serviceType].recordKeys[i])) == keccak256(abi.encodePacked(recordKey))) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            domains[domain].services[serviceType].recordKeys.push(recordKey);
        }

        domains[domain].services[serviceType].records[recordKey] = ServiceRecord({
            recordType: recordType,
            data: data,
            priority: priority,
            weight: weight
        });

        emit ServiceRecordSet(domain, serviceType, recordKey, recordType, data, priority, weight);
    }

    // Query service records for a domain and service type
    function queryService(
        string memory domain,
        string memory serviceType
    ) 
        external 
        view 
        onlyResolver 
        returns (
            string memory instanceName,
            ServiceRecord[] memory records
        ) 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        require(bytes(domains[domain].services[serviceType].instanceName).length > 0, "Service not registered");

        string memory instance = domains[domain].services[serviceType].instanceName;
        string[] memory keys = domains[domain].services[serviceType].recordKeys;
        ServiceRecord[] memory result = new ServiceRecord[](keys.length);

        for (uint256 i = 0; i < keys.length; i++) {
            result[i] = domains[domain].services[serviceType].records[keys[i]];
        }

        return (instance, result);
    }

    // Get all service types for a domain
    function getServiceTypes(string memory domain) 
        external 
        view 
        onlyResolver 
        returns (string[] memory) 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        return domains[domain].serviceTypes;
    }

    // Add or remove a resolver
    function updateResolver(address resolver, bool authorized) 
        external 
        onlyOwner 
    {
        require(resolver != address(0), "Invalid resolver address");
        resolvers[resolver] = authorized;
        emit ResolverUpdated(resolver, authorized);
    }

    // Get domain details
    function getDomainDetails(string memory domain) 
        external 
        view 
        returns (address, uint256, uint256) 
    {
        return (
            domains[domain].owner,
            domains[domain].registrationTime,
            domains[domain].expiryTime
        );
    }

    // Withdraw collected fees
    function withdrawFees() external onlyOwner {
        uint256 amount = address(this).balance;
        require(amount > 0, "No funds to withdraw");
        payable(owner).transfer(amount);
    }

    // Prevent accidental ETH deposits
    receive() external payable {
        revert("Use registerDomain or renewDomain to send ETH");
    }
}