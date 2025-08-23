// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// DNS Administrator smart contract for managing a decentralized name service
contract DNSAdministrator {
    // Struct to represent a domain
    struct Domain {
        address owner; // Owner of the domain
        uint256 registrationTime; // Timestamp of registration
        uint256 expiryTime; // Timestamp when domain expires
    }

    // Mapping to store domains
    mapping(string => Domain) public domains;

    // Mapping to store authorized administrators
    mapping(address => bool) public administrators;

    // Contract owner
    address public owner;

    // Registration fee (in wei)
    uint256 public registrationFee = 0.01 ether;

    // Registration duration (in seconds)
    uint256 public registrationDuration = 365 days;

    // Contract pause state
    bool public paused;

    // Event emitted when a domain is registered
    event DomainRegistered(string indexed domain, address owner, uint256 expiryTime);

    // Event emitted when a domain is transferred
    event DomainTransferred(string indexed domain, address newOwner);

    // Event emitted when a domain is renewed
    event DomainRenewed(string indexed domain, uint256 newExpiryTime);

    // Event emitted when an administrator is added
    event AdminAdded(address indexed admin);

    // Event emitted when an administrator is removed
    event AdminRemoved(address indexed admin);

    // Event emitted when registration fee is updated
    event RegistrationFeeUpdated(uint256 newFee);

    // Event emitted when registration duration is updated
    event RegistrationDurationUpdated(uint256 newDuration);

    // Event emitted when contract is paused or unpaused
    event Paused(bool isPaused);

    // Modifier to restrict actions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict actions to administrators or owner
    modifier onlyAdmin() {
        require(administrators[msg.sender] || msg.sender == owner, "Only admin or owner can call this function");
        _;
    }

    // Modifier to check if contract is not paused
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
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

    // Modifier to restrict actions to the domain owner
    modifier onlyDomainOwner(string memory domain) {
        require(domains[domain].owner == msg.sender, "Not the domain owner");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        _;
    }

    // Constructor to initialize the owner and set default admin
    constructor() {
        owner = msg.sender;
        administrators[msg.sender] = true;
        emit AdminAdded(msg.sender);
    }

    // Register a new domain
    function registerDomain(string memory domain) 
        external 
        payable 
        whenNotPaused 
        domainAvailable(domain) 
    {
        require(bytes(domain).length > 0, "Domain cannot be empty");
        require(msg.value >= registrationFee, "Insufficient registration fee");

        domains[domain] = Domain({
            owner: msg.sender,
            registrationTime: block.timestamp,
            expiryTime: block.timestamp + registrationDuration
        });

        // Refund excess payment
        if (msg.value > registrationFee) {
            payable(msg.sender).transfer(msg.value - registrationFee);
        }

        emit DomainRegistered(domain, msg.sender, block.timestamp + registrationDuration);
    }

    // Renew an existing domain
    function renewDomain(string memory domain) 
        external 
        payable 
        whenNotPaused 
        onlyDomainOwner(domain) 
    {
        require(msg.value >= registrationFee, "Insufficient renewal fee");

        domains[domain].expiryTime += registrationDuration;

        // Refund excess payment
        if (msg.value > registrationFee) {
            payable(msg.sender).transfer(msg.value - registrationFee);
        }

        emit DomainRenewed(domain, domains[domain].expiryTime);
    }

    // Transfer domain ownership (by domain owner or admin)
    function transferDomain(string memory domain, address newOwner) 
        external 
        whenNotPaused 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        require(newOwner != address(0), "Invalid new owner");
        require(msg.sender == domains[domain].owner || administrators[msg.sender], "Not authorized");

        domains[domain].owner = newOwner;
        emit DomainTransferred(domain, newOwner);
    }

    // Add an administrator
    function addAdmin(address admin) external onlyOwner {
        require(admin != address(0), "Invalid admin address");
        require(!administrators[admin], "Admin already exists");

        administrators[admin] = true;
        emit AdminAdded(admin);
    }

    // Remove an administrator
    function removeAdmin(address admin) external onlyOwner {
        require(administrators[admin], "Not an admin");
        require(admin != owner, "Cannot remove owner");

        administrators[admin] = false;
        emit AdminRemoved(admin);
    }

    // Update registration fee
    function updateRegistrationFee(uint256 newFee) external onlyOwner {
        require(newFee > 0, "Fee must be greater than 0");
        registrationFee = newFee;
        emit RegistrationFeeUpdated(newFee);
    }

    // Update registration duration
    function updateRegistrationDuration(uint256 newDuration) external onlyOwner {
        require(newDuration > 0, "Duration must be greater than 0");
        registrationDuration = newDuration;
        emit RegistrationDurationUpdated(newDuration);
    }

    // Pause or unpause the contract
    function setPaused(bool _paused) external onlyOwner {
        paused = _paused;
        emit Paused(_paused);
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