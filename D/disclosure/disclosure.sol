pragma solidity ^0.8.0;

// Disclosure contract for managing sensitive information disclosures
contract Disclosure {
    // Struct to store disclosure metadata
    struct DisclosureRecord {
        string title; // Title of the disclosure (e.g., "Financial Report Q3 2025")
        string dataHash; // Hash of the disclosure content (e.g., IPFS hash)
        string category; // Category (e.g., "Financial", "Legal", "Medical")
        address owner; // Owner of the disclosure
        uint256 creationTime; // Timestamp of creation
        bool isVerified; // Verification status
        mapping(address => bool) authorizedViewers; // Access control for viewing
    }

    // Mapping from disclosure ID to DisclosureRecord struct
    mapping(uint256 => DisclosureRecord) public disclosures;
    uint256 public disclosureCount; // Counter for disclosure IDs

    // Event emitted when a new disclosure is registered
    event DisclosureRegistered(uint256 disclosureId, string title, string category, address owner, uint256 creationTime);
    // Event emitted when a disclosure is verified
    event DisclosureVerified(uint256 disclosureId, address verifier);
    // Event emitted when access is granted
    event AccessGranted(uint256 disclosureId, address viewer);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 disclosureId, address viewer);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(uint256 disclosureId, address newOwner);

    // Modifier to check if caller is the disclosure owner
    modifier onlyOwner(uint256 _disclosureId) {
        require(disclosures[_disclosureId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if disclosure exists
    modifier disclosureExists(uint256 _disclosureId) {
        require(_disclosureId > 0 && _disclosureId <= disclosureCount, "Disclosure does not exist");
        _;
    }

    // Function to register a new disclosure
    function registerDisclosure(
        string memory _title,
        string memory _dataHash,
        string memory _category
    ) public {
        disclosureCount++;
        DisclosureRecord storage newDisclosure = disclosures[disclosureCount];
        newDisclosure.title = _title;
        newDisclosure.dataHash = _dataHash;
        newDisclosure.category = _category;
        newDisclosure.owner = msg.sender;
        newDisclosure.creationTime = block.timestamp;
        newDisclosure.isVerified = false; // Starts unverified
        newDisclosure.authorizedViewers[msg.sender] = true; // Owner gets access

        emit DisclosureRegistered(disclosureCount, _title, _category, msg.sender, block.timestamp);
    }

    // Function to verify a disclosure (e.g., by an authorized entity)
    function verifyDisclosure(uint256 _disclosureId) public disclosureExists(_disclosureId) {
        // In production, restrict to a specific verifier role
        require(!disclosures[_disclosureId].isVerified, "Disclosure already verified");
        disclosures[_disclosureId].isVerified = true;
        emit DisclosureVerified(_disclosureId, msg.sender);
    }

    // Function to grant view access to a disclosure's metadata
    function grantAccess(uint256 _disclosureId, address _viewer) public onlyOwner(_disclosureId) disclosureExists(_disclosureId) {
        require(_viewer != address(0), "Invalid viewer address");
        disclosures[_disclosureId].authorizedViewers[_viewer] = true;
        emit AccessGranted(_disclosureId, _viewer);
    }

    // Function to revoke view access to a disclosure's metadata
    function revokeAccess(uint256 _disclosureId, address _viewer) public onlyOwner(_disclosureId) disclosureExists(_disclosureId) {
        require(_viewer != disclosures[_disclosureId].owner, "Cannot revoke owner's access");
        disclosures[_disclosureId].authorizedViewers[_viewer] = false;
        emit AccessRevoked(_disclosureId, _viewer);
    }

    // Function to check if a user has view access
    function hasAccess(uint256 _disclosureId, address _viewer) public view disclosureExists(_disclosureId) returns (bool) {
        return disclosures[_disclosureId].authorizedViewers[_viewer];
    }

    // Function to get disclosure metadata (only for authorized viewers)
    function getDisclosureMetadata(uint256 _disclosureId) 
        public 
        view 
        disclosureExists(_disclosureId) 
        returns (
            string memory title,
            string memory dataHash,
            string memory category,
            address owner,
            uint256 creationTime,
            bool isVerified
        ) 
    {
        require(disclosures[_disclosureId].authorizedViewers[msg.sender], "Access denied");
        DisclosureRecord storage disclosure = disclosures[_disclosureId];
        return (
            disclosure.title,
            disclosure.dataHash,
            disclosure.category,
            disclosure.owner,
            disclosure.creationTime,
            disclosure.isVerified
        );
    }

    // Function to transfer ownership of a disclosure
    function transferOwnership(uint256 _disclosureId, address _newOwner) public onlyOwner(_disclosureId) disclosureExists(_disclosureId) {
        require(_newOwner != address(0), "Invalid new owner address");
        disclosures[_disclosureId].owner = _newOwner;
        disclosures[_disclosureId].authorizedViewers[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_disclosureId, _newOwner);
    }
}
