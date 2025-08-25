// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Decentralized Name System Security Extensions (DNSSEC) smart contract
contract DNSSEC {
    // Enum for record types
    enum RecordType { ADDR, TEXT }

    // Struct to represent a signed record
    struct SignedRecord {
        RecordType recordType; // Type of record (ADDR or TEXT)
        bytes data; // Record data (address for ADDR, string for TEXT)
        bytes signature; // Digital signature of the record
    }

    // Struct to represent a domain
    struct Domain {
        address owner; // Owner of the domain
        bytes publicKey; // Public key for signature verification
        uint256 registrationTime; // Timestamp of registration
        uint256 expiryTime; // Timestamp when domain expires
        mapping(string => SignedRecord) records; // Subdomain to signed record mapping
        string[] subdomains; // List of subdomains
    }

    // Mapping to store domains
    mapping(string => Domain) public domains;

    // Owner of the contract
    address public owner;

    // Authorized resolvers for record verification
    mapping(address => bool) public resolvers;

    // Registration fee (in wei)
    uint256 public constant REGISTRATION_FEE = 0.01 ether;

    // Default registration duration (1 year in seconds)
    uint256 public constant REGISTRATION_DURATION = 365 days;

    // Event emitted when a domain is registered
    event DomainRegistered(string indexed domain, address owner, bytes publicKey, uint256 expiryTime);

    // Event emitted when a signed record is set
    event RecordSet(string indexed domain, string subdomain, RecordType recordType, bytes data, bytes signature);

    // Event emitted when a record is verified
    event RecordVerified(string indexed domain, string subdomain, bool isValid);

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

    // Register a new domain with a public key
    function registerDomain(string memory domain, bytes memory publicKey) 
        external 
        payable 
        domainAvailable(domain) 
    {
        require(bytes(domain).length > 0, "Domain cannot be empty");
        require(publicKey.length > 0, "Public key cannot be empty");
        require(msg.value >= REGISTRATION_FEE, "Insufficient registration fee");

        domains[domain].owner = msg.sender;
        domains[domain].publicKey = publicKey;
        domains[domain].registrationTime = block.timestamp;
        domains[domain].expiryTime = block.timestamp + REGISTRATION_DURATION;

        // Refund excess payment
        if (msg.value > REGISTRATION_FEE) {
            payable(msg.sender).transfer(msg.value - REGISTRATION_FEE);
        }

        emit DomainRegistered(domain, msg.sender, publicKey, block.timestamp + REGISTRATION_DURATION);
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

    // Set a signed record for a domain or subdomain
    function setSignedRecord(
        string memory domain,
        string memory subdomain,
        RecordType recordType,
        bytes memory data,
        bytes memory signature
    ) 
        external 
        onlyDomainOwner(domain) 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        require(data.length > 0, "Record data cannot be empty");
        require(signature.length == 65, "Invalid signature length");
        if (recordType == RecordType.ADDR) {
            require(data.length == 20, "Invalid address length");
        }

        // Verify the signature
        bytes32 dataHash = keccak256(abi.encodePacked(domain, subdomain, recordType, data));
        address signer = recoverSigner(dataHash, signature);
        require(signer == domains[domain].owner, "Invalid signature");

        // Add subdomain to list if not already present
        if (bytes(subdomain).length > 0) {
            bool exists = false;
            for (uint256 i = 0; i < domains[domain].subdomains.length; i++) {
                if (keccak256(abi.encodePacked(domains[domain].subdomains[i])) == keccak256(abi.encodePacked(subdomain))) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                domains[domain].subdomains.push(subdomain);
            }
        }

        domains[domain].records[subdomain] = SignedRecord({
            recordType: recordType,
            data: data,
            signature: signature
        });

        emit RecordSet(domain, subdomain, recordType, data, signature);
    }

    // Verify and resolve a signed record
    function resolveAndVerify(string memory domain, string memory subdomain) 
        external 
        view 
        onlyResolver 
        returns (RecordType, bytes memory, bool) 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");

        SignedRecord memory record = domains[domain].records[subdomain];
        require(record.data.length > 0, "No record found");

        // Verify the signature
        bytes32 dataHash = keccak256(abi.encodePacked(domain, subdomain, record.recordType, record.data));
        address signer = recoverSigner(dataHash, record.signature);
        bool isValid = signer == domains[domain].owner;

        return (record.recordType, record.data, isValid);
    }

    // Get all subdomains for a domain
    function getSubdomains(string memory domain) 
        external 
        view 
        onlyResolver 
        returns (string[] memory) 
    {
        require(domains[domain].owner != address(0), "Domain not registered");
        require(block.timestamp <= domains[domain].expiryTime, "Domain expired");
        return domains[domain].subdomains;
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
        returns (address, bytes memory, uint256, uint256) 
    {
        return (
            domains[domain].owner,
            domains[domain].publicKey,
            domains[domain].registrationTime,
            domains[domain].expiryTime
        );
    }

    // Helper function to recover signer from a signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) 
        internal 
        pure 
        returns (address) 
    {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");
        return ecrecover(messageHash, v, r, s);
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