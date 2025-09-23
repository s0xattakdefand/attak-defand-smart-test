pragma solidity ^0.8.0;

// DisclosureLimitation contract for managing sensitive data with restricted access
contract DisclosureLimitation {
    // Struct to store sensitive data metadata
    struct SensitiveData {
        string title; // Title of the data (e.g., "Patient Record 001")
        string dataHash; // Hash of the data content (e.g., IPFS hash)
        string category; // Category (e.g., "Medical", "Financial", "Legal")
        address owner; // Owner of the data record
        uint256 creationTime; // Timestamp of creation
        bool isVerified; // Verification status
        mapping(address => bool) authorizedViewers; // Access control for viewing
    }

    // Mapping from data ID to SensitiveData struct
    mapping(uint256 => SensitiveData) public sensitiveDataRecords;
    uint256 public dataCount; // Counter for data IDs

    // Event emitted when a new data record is registered
    event DataRegistered(uint256 dataId, string title, string category, address owner, uint256 creationTime);
    // Event emitted when a data record is verified
    event DataVerified(uint256 dataId, address verifier);
    // Event emitted when access is granted
    event AccessGranted(uint256 dataId, address viewer);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 dataId, address viewer);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(uint256 dataId, address newOwner);
    // Event emitted when data is revoked
    event DataRevoked(uint256 dataId, address owner);

    // Modifier to check if caller is the data owner
    modifier onlyOwner(uint256 _dataId) {
        require(sensitiveDataRecords[_dataId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if data record exists
    modifier dataExists(uint256 _dataId) {
        require(_dataId > 0 && _dataId <= dataCount, "Data record does not exist");
        _;
    }

    // Modifier to check if data is not revoked
    modifier notRevoked(uint256 _dataId) {
        require(sensitiveDataRecords[_dataId].owner != address(0), "Data record has been revoked");
        _;
    }

    // Function to register a new sensitive data record
    function registerData(
        string memory _title,
        string memory _dataHash,
        string memory _category
    ) public {
        dataCount++;
        SensitiveData storage newData = sensitiveDataRecords[dataCount];
        newData.title = _title;
        newData.dataHash = _dataHash;
        newData.category = _category;
        newData.owner = msg.sender;
        newData.creationTime = block.timestamp;
        newData.isVerified = false; // Starts unverified
        newData.authorizedViewers[msg.sender] = true; // Owner gets access

        emit DataRegistered(dataCount, _title, _category, msg.sender, block.timestamp);
    }

    // Function to verify a data record (e.g., by an authorized entity)
    function verifyData(uint256 _dataId) public dataExists(_dataId) notRevoked(_dataId) {
        // In production, restrict to a specific verifier role
        require(!sensitiveDataRecords[_dataId].isVerified, "Data already verified");
        sensitiveDataRecords[_dataId].isVerified = true;
        emit DataVerified(_dataId, msg.sender);
    }

    // Function to grant view access to a data record's metadata
    function grantAccess(uint256 _dataId, address _viewer) public onlyOwner(_dataId) dataExists(_dataId) notRevoked(_dataId) {
        require(_viewer != address(0), "Invalid viewer address");
        sensitiveDataRecords[_dataId].authorizedViewers[_viewer] = true;
        emit AccessGranted(_dataId, _viewer);
    }

    // Function to revoke view access to a data record's metadata
    function revokeAccess(uint256 _dataId, address _viewer) public onlyOwner(_dataId) dataExists(_dataId) notRevoked(_dataId) {
        require(_viewer != sensitiveDataRecords[_dataId].owner, "Cannot revoke owner's access");
        sensitiveDataRecords[_dataId].authorizedViewers[_viewer] = false;
        emit AccessRevoked(_dataId, _viewer);
    }

    // Function to check if a user has view access
    function hasAccess(uint256 _dataId, address _viewer) public view dataExists(_dataId) notRevoked(_dataId) returns (bool) {
        return sensitiveDataRecords[_dataId].authorizedViewers[_viewer];
    }

    // Function to get data record metadata (only for authorized viewers)
    function getDataMetadata(uint256 _dataId) 
        public 
        view 
        dataExists(_dataId) 
        notRevoked(_dataId)
        returns (
            string memory title,
            string memory dataHash,
            string memory category,
            address owner,
            uint256 creationTime,
            bool isVerified
        ) 
    {
        require(sensitiveDataRecords[_dataId].authorizedViewers[msg.sender], "Access denied");
        SensitiveData storage data = sensitiveDataRecords[_dataId];
        return (
            data.title,
            data.dataHash,
            data.category,
            data.owner,
            data.creationTime,
            data.isVerified
        );
    }

    // Function to revoke a data record (e.g., to invalidate or delete access)
    function revokeData(uint256 _dataId) public onlyOwner(_dataId) dataExists(_dataId) notRevoked(_dataId) {
        sensitiveDataRecords[_dataId].owner = address(0); // Mark as revoked
        emit DataRevoked(_dataId, msg.sender);
    }

    // Function to transfer ownership of a data record
    function transferOwnership(uint256 _dataId, address _newOwner) public onlyOwner(_dataId) dataExists(_dataId) notRevoked(_dataId) {
        require(_newOwner != address(0), "Invalid new owner address");
        sensitiveDataRecords[_dataId].owner = _newOwner;
        sensitiveDataRecords[_dataId].authorizedViewers[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_dataId, _newOwner);
    }
}
