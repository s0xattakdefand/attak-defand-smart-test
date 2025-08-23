// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Decentralized Name Service (DNS) smart contract
contract DNS {
    // Enum for record types
    enum RecordType { ADDR, TEXT }

    // Struct to represent a record
    struct Record {
        RecordType recordType; // Type of record (ADDR or TEXT)
        bytes data; // Record data (address for ADDR, string for TEXT)
    }

    // Struct to represent a domain
    struct Domain {
        address owner; // Owner of the domain
        uint256 registrationTime; // Timestamp of registration
        uint256 expiryTime; // Timestamp when domain expires
        mapping(string => Record) records; // Subdomain to record mapping
        mapping(string => address) subdomainOwners; // Subdomain ownership
    }

    // Mapping to store domains
    mapping(string => Domain) public domains;

    // Owner of the contract
    address public owner;

    // Registration fee (in wei)
    uint256 public constant REGISTRATION_FEE = 0.01 ether;

    // Default registration duration (1 year in seconds)
    uint256 public constant REGISTRATION_DURATION = 365 days;

    // Event emitted when a domain is registered
    event DomainRegistered(string indexed domain, address owner, uint256 expiryTime);

    // Event emitted when a subdomain is assigned
    event SubdomainAssigned(string indexed domain, string subdomain, address owner);

    // Event emitted when a record is set
    event RecordSet(string indexed domain, string subdomain, RecordType recordType, bytes data);

    // Event emitted when a domain is renewed
    event DomainRenewed(string indexed domain, uint256 newExpiryTime);

    // Event emitted when a domain is transferred
    event DomainTransferred(string indexed domain, address newOwner);

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

    // Constructor to initialize the owner
    constructor() {
        owner = msg.sender;
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

    // Assign a subdomain to an owner
    function assignSubdomain(string memory domain, string memory subdomain, address subdomainOwner) 
        external 
        onlyDomainOwner(domain) 
    {
        require(subdomainOwner != address(0), "Invalid subdomain owner");
        require(bytes(subdomain).length > 0, "Subdomain cannot be empty");

        domains[domain].subdomainOwners[subdomain] = subdomainOwner;
        emit SubdomainAssigned(domain, subdomain, subdomainOwner);
    }

    // Set a record for a domain or subdomain
    function setRecord(
        string memory domain,
        string memory subdomain,
        RecordType recordType,
        bytes memory data
    ) 
        external 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        require(bytes(subdomain).length == 0 || domains[domain].subdomainOwners[subdomain] == msg.sender, "Not subdomain owner");
        require(bytes(subdomain).length > 0 || domains[domain].owner == msg.sender, "Not domain owner");
        require(data.length > 0, "Record data cannot be empty");

        if (recordType == RecordType.ADDR) {
            // Ensure data is a valid address (20 bytes)
            require(data.length == 20, "Invalid address length");
        }

        domains[domain].records[subdomain] = Record({
            recordType: recordType,
            data: data
        });

        emit RecordSet(domain, subdomain, recordType, data);
    }

    // Resolve a domain or subdomain to its record
    function resolve(string memory domain, string memory subdomain) 
        external 
        view 
        returns (RecordType, bytes memory) 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");

        Record memory record = domains[domain].records[subdomain];
        require(record.data.length > 0, "No record found");

        return (record.recordType, record.data);
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

    // Get subdomain owner
    function getSubdomainOwner(string memory domain, string memory subdomain) 
        external 
        view 
        returns (address) 
    {
        return domains[domain].subdomainOwners[subdomain];
    }

    // Withdraw collected fees by contract owner
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