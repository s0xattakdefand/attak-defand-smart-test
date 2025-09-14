pragma solidity ^0.8.0;

// DirectBlackWireline contract for managing wireline installations
contract DirectBlackWireline {
    // Struct to store wireline metadata
    struct Wireline {
        string wirelineType; // Type of wireline (e.g., analog telephone, alarm line)
        string specsHash; // Hash of specifications (e.g., IPFS hash for detailed specs)
        string location; // Location of wireline installation
        address owner; // Owner of the wireline record
        uint256 registrationTime; // Timestamp of registration
        bool isVerified; // Verification status
        mapping(address => bool) authorizedViewers; // Access control for metadata
    }

    // Mapping from wireline ID to Wireline struct
    mapping(uint256 => Wireline) public wirelines;
    uint256 public wirelineCount; // Counter for wireline IDs

    // Event emitted when a new wireline is registered
    event WirelineRegistered(uint256 wirelineId, string wirelineType, address owner, uint256 registrationTime);
    // Event emitted when a wireline is verified
    event WirelineVerified(uint256 wirelineId, address verifier);
    // Event emitted when access is granted
    event AccessGranted(uint256 wirelineId, address viewer);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 wirelineId, address viewer);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(uint256 wirelineId, address newOwner);

    // Modifier to check if caller is the wireline owner
    modifier onlyOwner(uint256 _wirelineId) {
        require(wirelines[_wirelineId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if wireline exists
    modifier wirelineExists(uint256 _wirelineId) {
        require(_wirelineId > 0 && _wirelineId <= wirelineCount, "Wireline does not exist");
        _;
    }

    // Function to register a new wireline
    function registerWireline(string memory _wirelineType, string memory _specsHash, string memory _location) public {
        wirelineCount++;
        Wireline storage newWireline = wirelines[wirelineCount];
        newWireline.wirelineType = _wirelineType;
        newWireline.specsHash = _specsHash;
        newWireline.location = _location;
        newWireline.owner = msg.sender;
        newWireline.registrationTime = block.timestamp;
        newWireline.isVerified = false; // Wireline starts unverified
        newWireline.authorizedViewers[msg.sender] = true; // Owner gets view access

        emit WirelineRegistered(wirelineCount, _wirelineType, msg.sender, block.timestamp);
    }

    // Function to verify a wireline (e.g., by an authorized entity)
    function verifyWireline(uint256 _wirelineId) public wirelineExists(_wirelineId) {
        // In production, restrict to a specific verifier role
        require(!wirelines[_wirelineId].isVerified, "Wireline already verified");
        wirelines[_wirelineId].isVerified = true;
        emit WirelineVerified(_wirelineId, msg.sender);
    }

    // Function to grant view access to a wireline's metadata
    function grantAccess(uint256 _wirelineId, address _viewer) public onlyOwner(_wirelineId) wirelineExists(_wirelineId) {
        require(_viewer != address(0), "Invalid viewer address");
        wirelines[_wirelineId].authorizedViewers[_viewer] = true;
        emit AccessGranted(_wirelineId, _viewer);
    }

    // Function to revoke view access to a wireline's metadata
    function revokeAccess(uint256 _wirelineId, address _viewer) public onlyOwner(_wirelineId) wirelineExists(_wirelineId) {
        require(_viewer != wirelines[_wirelineId].owner, "Cannot revoke owner's access");
        wirelines[_wirelineId].authorizedViewers[_viewer] = false;
        emit AccessRevoked(_wirelineId, _viewer);
    }

    // Function to check if a user has view access
    function hasAccess(uint256 _wirelineId, address _viewer) public view wirelineExists(_wirelineId) returns (bool) {
        return wirelines[_wirelineId].authorizedViewers[_viewer];
    }

    // Function to get wireline metadata (only for authorized viewers)
    function getWirelineMetadata(uint256 _wirelineId) 
        public 
        view 
        wirelineExists(_wirelineId) 
        returns (string memory wirelineType, string memory specsHash, string memory location, address owner, uint256 registrationTime, bool isVerified) 
    {
        require(wirelines[_wirelineId].authorizedViewers[msg.sender], "Access denied");
        Wireline storage wireline = wirelines[_wirelineId];
        return (wireline.wirelineType, wireline.specsHash, wireline.location, wireline.owner, wireline.registrationTime, wireline.isVerified);
    }

    // Function to transfer ownership of a wireline
    function transferOwnership(uint256 _wirelineId, address _newOwner) public onlyOwner(_wirelineId) wirelineExists(_wirelineId) {
        require(_newOwner != address(0), "Invalid new owner address");
        wirelines[_wirelineId].owner = _newOwner;
        wirelines[_wirelineId].authorizedViewers[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_wirelineId, _newOwner);
    }
}
