// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalSecurityByDesign
 * @dev A smart contract for managing secure digital assets with built-in security features.
 * Supports role-based access control, versioning, paid access, verification, and chain-of-custody tracking.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalSecurityByDesign {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or accessor
        string action; // Description of the action (e.g., "Asset created", "Access granted")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent an asset version
    struct AssetVersion {
        bytes32 assetHash; // Keccak-256 hash of the asset content (e.g., IPFS hash)
        string description; // Description of the asset version
        uint256 versionNumber; // Version number of the asset
        uint256 timestamp; // Timestamp of version creation
    }

    // Struct to represent a secure digital asset
    struct SecureAsset {
        string assetName; // Name of the asset
        string assetType; // Type of asset (e.g., "Data", "Document", "Configuration")
        address owner; // Owner of the asset
        uint256 price; // Price in wei for accessing the asset
        mapping(address => bool) authorizedUsers; // Mapping of authorized users
        AssetVersion[] versions; // Array of asset versions
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of asset creation
        bool exists; // Flag to check if asset exists
        bool isLocked; // Flag to lock asset from further modifications
    }

    // Mapping to store secure assets by their unique ID
    mapping(bytes32 => SecureAsset) public secureAssets;
    // Mapping to track assets by owner
    mapping(address => bytes32[]) public ownerAssets;

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    // Mapping to track roles for addresses
    mapping(address => mapping(bytes32 => bool)) public roles;

    // Event emitted when a new secure asset is created
    event AssetCreated(bytes32 indexed assetId, string assetName, address indexed owner, string assetType, bytes32 initialAssetHash);
    // Event emitted when a new asset version is added
    event AssetVersionAdded(bytes32 indexed assetId, uint256 versionNumber, bytes32 assetHash, string description);
    // Event emitted when an asset is updated
    event AssetUpdated(bytes32 indexed assetId, string newAssetName, string newAssetType, uint256 newPrice);
    // Event emitted when an asset is locked
    event AssetLocked(bytes32 indexed assetId, address indexed owner);
    // Event emitted when asset ownership is transferred
    event AssetTransferred(bytes32 indexed assetId, address indexed newOwner);
    // Event emitted when a user is authorized
    event UserAuthorized(bytes32 indexed assetId, address indexed user);
    // Event emitted when an asset is accessed (purchased)
    event AssetAccessed(bytes32 indexed assetId, address indexed user, uint256 price);
    // Event emitted when an asset version is verified
    event AssetVerified(bytes32 indexed assetId, uint256 versionNumber, address indexed verifier, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed assetId, address indexed custodian, string action);
    // Event emitted when a role is assigned
    event RoleAssigned(address indexed user, bytes32 indexed role);

    // Modifier to check if the caller has a specific role
    modifier onlyRole(bytes32 role) {
        require(roles[msg.sender][role], "Caller does not have the required role");
        _;
    }

    // Modifier to check if the caller is the owner of the asset
    modifier onlyOwner(bytes32 assetId) {
        require(secureAssets[assetId].owner == msg.sender, "Only the owner can perform this action");
        require(secureAssets[assetId].exists, "Asset does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized user or owner
    modifier onlyAuthorized(bytes32 assetId) {
        require(secureAssets[assetId].exists, "Asset does not exist");
        require(
            secureAssets[assetId].owner == msg.sender || 
            secureAssets[assetId].authorizedUsers[msg.sender] || 
            roles[msg.sender][VERIFIER_ROLE],
            "Only authorized users, owner, or verifiers can perform this action"
        );
        _;
    }

    // Modifier to check if the asset is not locked
    modifier notLocked(bytes32 assetId) {
        require(!secureAssets[assetId].isLocked, "Asset is locked and cannot be modified");
        _;
    }

    /**
     * @dev Constructor to set the deployer as the initial admin
     */
    constructor() {
        roles[msg.sender][ADMIN_ROLE] = true;
        emit RoleAssigned(msg.sender, ADMIN_ROLE);
    }

    /**
     * @dev Assigns a role to a user (admin only).
     * @param _user The address of the user.
     * @param _role The role to assign (ADMIN_ROLE or VERIFIER_ROLE).
     */
    function assignRole(address _user, bytes32 _role) public onlyRole(ADMIN_ROLE) {
        require(_user != address(0), "User address cannot be zero");
        require(_role == ADMIN_ROLE || _role == VERIFIER_ROLE, "Invalid role");
        roles[_user][_role] = true;
        emit RoleAssigned(_user, _role);
    }

    /**
     * @dev Creates a new secure digital asset with an initial version.
     * @param _assetHash The Keccak-256 hash of the initial asset content.
     * @param _assetName The name of the asset.
     * @param _assetType The type of asset (e.g., "Data", "Document").
     * @param _description The description of the initial asset version.
     * @param _price The price in wei for accessing the asset.
     * @return assetId The unique ID of the asset.
     */
    function createAsset(
        bytes32 _assetHash,
        string memory _assetName,
        string memory _assetType,
        string memory _description,
        uint256 _price
    ) public returns (bytes32) {
        require(_assetHash != bytes32(0), "Asset hash cannot be empty");
        require(bytes(_assetName).length > 0, "Asset name cannot be empty");
        require(bytes(_assetType).length > 0, "Asset type cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(_price >= 0, "Price cannot be negative");

        // Generate a unique asset ID
        bytes32 assetId = keccak256(abi.encodePacked(_assetHash, msg.sender, block.timestamp));
        
        // Ensure the asset doesn't already exist
        require(!secureAssets[assetId].exists, "Asset with this ID already exists");

        // Initialize the asset
        SecureAsset storage newAsset = secureAssets[assetId];
        newAsset.assetName = _assetName;
        newAsset.assetType = _assetType;
        newAsset.owner = msg.sender;
        newAsset.price = _price;
        newAsset.timestamp = block.timestamp;
        newAsset.exists = true;
        newAsset.isLocked = false;

        // Add initial version
        newAsset.versions.push(AssetVersion({
            assetHash: _assetHash,
            description: _description,
            versionNumber: 1,
            timestamp: block.timestamp
        }));

        // Initialize the custody log
        newAsset.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Asset created",
            timestamp: block.timestamp
        }));

        // Add asset ID to owner's list
        ownerAssets[msg.sender].push(assetId);

        // Emit events
        emit AssetCreated(assetId, _assetName, msg.sender, _assetType, _assetHash);
        emit AssetVersionAdded(assetId, 1, _assetHash, _description);
        emit CustodyUpdated(assetId, msg.sender, "Asset created");

        return assetId;
    }

    /**
     * @dev Adds a new version to an existing asset.
     * @param _assetId The ID of the asset.
     * @param _assetHash The Keccak-256 hash of the new asset content.
     * @param _description The description of the new asset version.
     */
    function addAssetVersion(
        bytes32 _assetId,
        bytes32 _assetHash,
        string memory _description
    ) public onlyOwner(_assetId) notLocked(_assetId) {
        require(_assetHash != bytes32(0), "Asset hash cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        SecureAsset storage asset = secureAssets[_assetId];
        uint256 newVersionNumber = asset.versions.length + 1;

        // Add new version
        asset.versions.push(AssetVersion({
            assetHash: _assetHash,
            description: _description,
            versionNumber: newVersionNumber,
            timestamp: block.timestamp
        }));

        // Add custody log entry
        asset.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "New asset version added",
            timestamp: block.timestamp
        }));

        // Emit events
        emit AssetVersionAdded(_assetId, newVersionNumber, _assetHash, _description);
        emit CustodyUpdated(_assetId, msg.sender, "New asset version added");
    }

    /**
     * @dev Updates the name, type, or price of an existing asset.
     * @param _assetId The ID of the asset.
     * @param _newAssetName The new name for the asset.
     * @param _newAssetType The new asset type.
     * @param _newPrice The new price in wei.
     */
    function updateAsset(
        bytes32 _assetId,
        string memory _newAssetName,
        string memory _newAssetType,
        uint256 _newPrice
    ) public onlyOwner(_assetId) notLocked(_assetId) {
        require(bytes(_newAssetName).length > 0, "Asset name cannot be empty");
        require(bytes(_newAssetType).length > 0, "Asset type cannot be empty");
        require(_newPrice >= 0, "Price cannot be negative");

        SecureAsset storage asset = secureAssets[_assetId];
        asset.assetName = _newAssetName;
        asset.assetType = _newAssetType;
        asset.price = _newPrice;

        // Add custody log entry
        asset.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Asset updated",
            timestamp: block.timestamp
        }));

        // Emit events
        emit AssetUpdated(_assetId, _newAssetName, _newAssetType, _newPrice);
        emit CustodyUpdated(_assetId, msg.sender, "Asset updated");
    }

    /**
     * @dev Locks an asset to prevent further modifications.
     * @param _assetId The ID of the asset.
     */
    function lockAsset(bytes32 _assetId) public onlyOwner(_assetId) notLocked(_assetId) {
        secureAssets[_assetId].isLocked = true;

        // Add custody log entry
        secureAssets[_assetId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Asset locked",
            timestamp: block.timestamp
        }));

        // Emit events
        emit AssetLocked(_assetId, msg.sender);
        emit CustodyUpdated(_assetId, msg.sender, "Asset locked");
    }

    /**
     * @dev Transfers ownership of an asset to a new address.
     * @param _assetId The ID of the asset.
     * @param _newOwner The address of the new owner.
     */
    function transferAssetOwnership(bytes32 _assetId, address _newOwner) public onlyOwner(_assetId) notLocked(_assetId) {
        require(_newOwner != address(0), "New owner address cannot be zero");
        require(_newOwner != secureAssets[_assetId].owner, "New owner must be different");

        // Update ownership
        secureAssets[_assetId].owner = _newOwner;

        // Add custody log entry
        secureAssets[_assetId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Ownership transferred to new owner",
            timestamp: block.timestamp
        }));

        // Update ownerAssets mappings
        bytes32[] storage ownerRecords = ownerAssets[msg.sender];
        for (uint256 i = 0; i < ownerRecords.length; i++) {
            if (ownerRecords[i] == _assetId) {
                ownerRecords[i] = ownerRecords[ownerRecords.length - 1];
                ownerRecords.pop();
                break;
            }
        }
        ownerAssets[_newOwner].push(_assetId);

        // Emit events
        emit AssetTransferred(_assetId, _newOwner);
        emit CustodyUpdated(_assetId, msg.sender, "Ownership transferred to new owner");
    }

    /**
     * @dev Authorizes a user to access an asset.
     * @param _assetId The ID of the asset.
     * @param _user The address of the user to authorize.
     */
    function authorizeUser(bytes32 _assetId, address _user) public onlyOwner(_assetId) notLocked(_assetId) {
        require(_user != address(0), "User address cannot be zero");
        require(!secureAssets[_assetId].authorizedUsers[_user], "User already authorized");

        secureAssets[_assetId].authorizedUsers[_user] = true;

        // Add custody log entry
        secureAssets[_assetId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "User authorized",
            timestamp: block.timestamp
        }));

        // Emit events
        emit UserAuthorized(_assetId, _user);
        emit CustodyUpdated(_assetId, msg.sender, "User authorized");
    }

    /**
     * @dev Allows a user to access (purchase) an asset by paying the specified price.
     * @param _assetId The ID of the asset.
     */
    function accessAsset(bytes32 _assetId) public payable {
        require(secureAssets[_assetId].exists, "Asset does not exist");
        require(msg.value >= secureAssets[_assetId].price, "Insufficient payment");
        require(msg.sender != secureAssets[_assetId].owner, "Owner cannot purchase own asset");

        SecureAsset storage asset = secureAssets[_assetId];

        // Authorize user if not already authorized
        if (!asset.authorizedUsers[msg.sender]) {
            asset.authorizedUsers[msg.sender] = true;
        }

        // Transfer payment to the owner
        address owner = asset.owner;
        uint256 price = asset.price;
        (bool success, ) = owner.call{value: price}("");
        require(success, "Payment transfer failed");

        // Refund excess payment if any
        if (msg.value > price) {
            (bool refundSuccess, ) = msg.sender.call{value: msg.value - price}("");
            require(refundSuccess, "Refund transfer failed");
        }

        // Add custody log entry
        asset.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Asset accessed",
            timestamp: block.timestamp
        }));

        // Emit events
        emit AssetAccessed(_assetId, msg.sender, price);
        emit CustodyUpdated(_assetId, msg.sender, "Asset accessed");
    }

    /**
     * @dev Verifies an asset version against provided asset content hash.
     * @param _assetId The ID of the asset.
     * @param _versionNumber The version number to verify.
     * @param _assetHash The hash of the asset content to verify.
     * @return isValid True if the asset hash matches the stored hash for the version.
     */
    function verifyAsset(bytes32 _assetId, uint256 _versionNumber, bytes32 _assetHash) 
        public 
        onlyAuthorized(_assetId) 
        returns (bool) 
    {
        require(secureAssets[_assetId].exists, "Asset does not exist");
        require(_versionNumber > 0 && _versionNumber <= secureAssets[_assetId].versions.length, "Invalid version number");
        require(_assetHash != bytes32(0), "Asset hash cannot be empty");

        AssetVersion storage version = secureAssets[_assetId].versions[_versionNumber - 1];
        bool isValid = (_assetHash == version.assetHash);

        // Emit event
        emit AssetVerified(_assetId, _versionNumber, msg.sender, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a secure asset.
     * @param _assetId The ID of the asset.
     * @return assetName The name of the asset.
     * @return assetType The type of asset.
     * @return owner The owner of the asset.
     * @return price The price for accessing the asset.
     * @return timestamp The timestamp of asset creation.
     * @return isLocked Whether the asset is locked.
     */
    function getAsset(bytes32 _assetId)
        public
        view
        onlyAuthorized(_assetId)
        returns (
            string memory assetName,
            string memory assetType,
            address owner,
            uint256 price,
            uint256 timestamp,
            bool isLocked
        )
    {
        require(secureAssets[_assetId].exists, "Asset does not exist");
        SecureAsset storage asset = secureAssets[_assetId];
        return (
            asset.assetName,
            asset.assetType,
            asset.owner,
            asset.price,
            asset.timestamp,
            asset.isLocked
        );
    }

    /**
     * @dev Retrieves the details of a specific asset version.
     * @param _assetId The ID of the asset.
     * @param _versionNumber The version number to retrieve.
     * @return assetHash The hash of the asset content.
     * @return description The description of the version.
     * @return versionNumber The version number.
     * @return timestamp The timestamp of version creation.
     */
    function getAssetVersion(bytes32 _assetId, uint256 _versionNumber)
        public
        view
        onlyAuthorized(_assetId)
        returns (
            bytes32 assetHash,
            string memory description,
            uint256 versionNumber,
            uint256 timestamp
        )
    {
        require(secureAssets[_assetId].exists, "Asset does not exist");
        require(_versionNumber > 0 && _versionNumber <= secureAssets[_assetId].versions.length, "Invalid version number");
        AssetVersion storage version = secureAssets[_assetId].versions[_versionNumber - 1];
        return (
            version.assetHash,
            version.description,
            version.versionNumber,
            version.timestamp
        );
    }

    /**
     * @dev Checks if a user is authorized for an asset.
     * @param _assetId The ID of the asset.
     * @param _user The address of the user.
     * @return True if the user is authorized, false otherwise.
     */
    function isUserAuthorized(bytes32 _assetId, address _user)
        public
        view
        onlyOwner(_assetId)
        returns (bool)
    {
        return secureAssets[_assetId].authorizedUsers[_user];
    }

    /**
     * @dev Retrieves the chain-of-custody log for an asset.
     * @param _assetId The ID of the asset.
     * @return custodians The array of custodian addresses.
     * @return actions The array of action descriptions.
     * @return timestamps The array of action timestamps.
     */
    function getCustodyLog(bytes32 _assetId)
        public
        view
        onlyAuthorized(_assetId)
        returns (
            address[] memory custodians,
            string[] memory actions,
            uint256[] memory timestamps
        )
    {
        require(secureAssets[_assetId].exists, "Asset does not exist");
        SecureAsset storage asset = secureAssets[_assetId];
        uint256 logLength = asset.custodyLog.length;

        custodians = new address[](logLength);
        actions = new string[](logLength);
        timestamps = new uint256[](logLength);

        for (uint256 i = 0; i < logLength; i++) {
            custodians[i] = asset.custodyLog[i].custodian;
            actions[i] = asset.custodyLog[i].action;
            timestamps[i] = asset.custodyLog[i].timestamp;
        }

        return (custodians, actions, timestamps);
    }

    /**
     * @dev Retrieves the list of asset IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of asset IDs.
     */
    function getOwnerAssets(address _owner) public view returns (bytes32[] memory) {
        return ownerAssets[_owner];
    }
}