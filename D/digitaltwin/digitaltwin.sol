// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalTwin
 * @dev A smart contract for managing digital twins of physical assets, with state updates, access control, and auditability.
 * Supports creation, updating, and verification of digital twin records, with chain-of-custody tracking.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalTwin {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or accessor
        string action; // Description of the action (e.g., "Twin created", "State updated")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent a digital twin
    struct Twin {
        bytes32 stateHash; // Keccak-256 hash of the current state (e.g., JSON of attributes)
        address creator; // Address of the twin creator
        string description; // Description of the physical asset
        string assetType; // Type of asset (e.g., "Sensor", "Vehicle", "Machine")
        address owner; // Owner of the digital twin record
        uint256 price; // Price in wei for accessing twin data
        mapping(address => bool) authorizedAccessors; // Mapping of authorized accessors
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of twin creation
        bool exists; // Flag to check if twin exists
        bool isLocked; // Flag to lock twin from further updates
    }

    // Mapping to store digital twins by their unique ID
    mapping(bytes32 => Twin) public twins;
    // Mapping to track twins by owner
    mapping(address => bytes32[]) public ownerTwins;

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant ACCESSOR_ROLE = keccak256("ACCESSOR_ROLE");

    // Mapping to track roles for addresses
    mapping(address => mapping(bytes32 => bool)) public roles;

    // Event emitted when a new digital twin is created
    event TwinCreated(bytes32 indexed twinId, bytes32 stateHash, address indexed creator, string description, string assetType);
    // Event emitted when a twin's state is updated
    event TwinUpdated(bytes32 indexed twinId, bytes32 newStateHash, string newDescription, string newAssetType, uint256 newPrice);
    // Event emitted when a twin is locked
    event TwinLocked(bytes32 indexed twinId, address indexed owner);
    // Event emitted when twin ownership is transferred
    event TwinTransferred(bytes32 indexed twinId, address indexed newOwner);
    // Event emitted when an accessor is authorized
    event AccessorAuthorized(bytes32 indexed twinId, address indexed accessor);
    // Event emitted when a twin is accessed (purchased)
    event TwinAccessed(bytes32 indexed twinId, address indexed accessor, uint256 price);
    // Event emitted when a twin's state is verified
    event TwinVerified(bytes32 indexed twinId, address indexed accessor, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed twinId, address indexed custodian, string action);
    // Event emitted when a role is assigned
    event RoleAssigned(address indexed user, bytes32 indexed role);

    // Modifier to check if the caller has a specific role
    modifier onlyRole(bytes32 role) {
        require(roles[msg.sender][role], "Caller does not have the required role");
        _;
    }

    // Modifier to check if the caller is the owner of the twin
    modifier onlyOwner(bytes32 twinId) {
        require(twins[twinId].owner == msg.sender, "Only the owner can perform this action");
        require(twins[twinId].exists, "Digital twin does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized accessor or owner
    modifier onlyAuthorized(bytes32 twinId) {
        require(twins[twinId].exists, "Digital twin does not exist");
        require(
            twins[twinId].owner == msg.sender || 
            twins[twinId].authorizedAccessors[msg.sender] || 
            roles[msg.sender][ACCESSOR_ROLE],
            "Only authorized accessors, owner, or role-based accessors can perform this action"
        );
        _;
    }

    // Modifier to check if the twin is not locked
    modifier notLocked(bytes32 twinId) {
        require(!twins[twinId].isLocked, "Digital twin is locked and cannot be modified");
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
     * @param _role The role to assign (ADMIN_ROLE or ACCESSOR_ROLE).
     */
    function assignRole(address _user, bytes32 _role) public onlyRole(ADMIN_ROLE) {
        require(_user != address(0), "User address cannot be zero");
        require(_role == ADMIN_ROLE || _role == ACCESSOR_ROLE, "Invalid role");
        roles[_user][_role] = true;
        emit RoleAssigned(_user, _role);
    }

    /**
     * @dev Creates a new digital twin for a physical asset.
     * @param _stateHash The Keccak-256 hash of the initial state (e.g., JSON of attributes).
     * @param _description The description of the physical asset.
     * @param _assetType The type of asset (e.g., "Sensor", "Vehicle").
     * @param _price The price in wei for accessing twin data.
     * @return twinId The unique ID of the digital twin.
     */
    function createTwin(
        bytes32 _stateHash,
        string memory _description,
        string memory _assetType,
        uint256 _price
    ) public returns (bytes32) {
        require(_stateHash != bytes32(0), "State hash cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(bytes(_assetType).length > 0, "Asset type cannot be empty");
        require(_price >= 0, "Price cannot be negative");

        // Generate a unique twin ID
        bytes32 twinId = keccak256(abi.encodePacked(_stateHash, msg.sender, block.timestamp));
        
        // Ensure the twin doesn't already exist
        require(!twins[twinId].exists, "Digital twin with this ID already exists");

        // Initialize the digital twin
        Twin storage newTwin = twins[twinId];
        newTwin.stateHash = _stateHash;
        newTwin.creator = msg.sender;
        newTwin.description = _description;
        newTwin.assetType = _assetType;
        newTwin.owner = msg.sender;
        newTwin.price = _price;
        newTwin.timestamp = block.timestamp;
        newTwin.exists = true;
        newTwin.isLocked = false;

        // Initialize the custody log
        newTwin.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Twin created",
            timestamp: block.timestamp
        }));

        // Add twin ID to owner's list
        ownerTwins[msg.sender].push(twinId);

        // Emit events
        emit TwinCreated(twinId, _stateHash, msg.sender, _description, _assetType);
        emit CustodyUpdated(twinId, msg.sender, "Twin created");

        return twinId;
    }

    /**
     * @dev Updates the state, description, asset type, or price of an existing digital twin.
     * @param _twinId The ID of the digital twin.
     * @param _newStateHash The new Keccak-256 hash of the state.
     * @param _newDescription The new description for the twin.
     * @param _newAssetType The new asset type.
     * @param _newPrice The new price in wei.
     */
    function updateTwin(
        bytes32 _twinId,
        bytes32 _newStateHash,
        string memory _newDescription,
        string memory _newAssetType,
        uint256 _newPrice
    ) public onlyOwner(_twinId) notLocked(_twinId) {
        require(_newStateHash != bytes32(0), "State hash cannot be empty");
        require(bytes(_newDescription).length > 0, "Description cannot be empty");
        require(bytes(_newAssetType).length > 0, "Asset type cannot be empty");
        require(_newPrice >= 0, "Price cannot be negative");

        Twin storage twin = twins[_twinId];
        twin.stateHash = _newStateHash;
        twin.description = _newDescription;
        twin.assetType = _newAssetType;
        twin.price = _newPrice;

        // Add custody log entry
        twin.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "State updated",
            timestamp: block.timestamp
        }));

        // Emit events
        emit TwinUpdated(_twinId, _newStateHash, _newDescription, _newAssetType, _newPrice);
        emit CustodyUpdated(_twinId, msg.sender, "State updated");
    }

    /**
     * @dev Locks a digital twin to prevent further updates.
     * @param _twinId The ID of the digital twin.
     */
    function lockTwin(bytes32 _twinId) public onlyOwner(_twinId) notLocked(_twinId) {
        twins[_twinId].isLocked = true;

        // Add custody log entry
        twins[_twinId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Twin locked",
            timestamp: block.timestamp
        }));

        // Emit events
        emit TwinLocked(_twinId, msg.sender);
        emit CustodyUpdated(_twinId, msg.sender, "Twin locked");
    }

    /**
     * @dev Transfers ownership of a digital twin to a new address.
     * @param _twinId The ID of the digital twin.
     * @param _newOwner The address of the new owner.
     */
    function transferTwinOwnership(bytes32 _twinId, address _newOwner) public onlyOwner(_twinId) notLocked(_twinId) {
        require(_newOwner != address(0), "New owner address cannot be zero");
        require(_newOwner != twins[_twinId].owner, "New owner must be different");

        // Update ownership
        twins[_twinId].owner = _newOwner;

        // Add custody log entry
        twins[_twinId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Ownership transferred to new owner",
            timestamp: block.timestamp
        }));

        // Update ownerTwins mappings
        bytes32[] storage ownerRecords = ownerTwins[msg.sender];
        for (uint256 i = 0; i < ownerRecords.length; i++) {
            if (ownerRecords[i] == _twinId) {
                ownerRecords[i] = ownerRecords[ownerRecords.length - 1];
                ownerRecords.pop();
                break;
            }
        }
        ownerTwins[_newOwner].push(_twinId);

        // Emit events
        emit TwinTransferred(_twinId, _newOwner);
        emit CustodyUpdated(_twinId, msg.sender, "Ownership transferred to new owner");
    }

    /**
     * @dev Authorizes an accessor to view a digital twin's data.
     * @param _twinId The ID of the digital twin.
     * @param _accessor The address of the accessor to authorize.
     */
    function authorizeAccessor(bytes32 _twinId, address _accessor) public onlyOwner(_twinId) notLocked(_twinId) {
        require(_accessor != address(0), "Accessor address cannot be zero");
        require(!twins[_twinId].authorizedAccessors[_accessor], "Accessor already authorized");

        twins[_twinId].authorizedAccessors[_accessor] = true;

        // Add custody log entry
        twins[_twinId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Accessor authorized",
            timestamp: block.timestamp
        }));

        // Emit events
        emit AccessorAuthorized(_twinId, _accessor);
        emit CustodyUpdated(_twinId, msg.sender, "Accessor authorized");
    }

    /**
     * @dev Allows an accessor to access (purchase) a digital twin by paying the specified price.
     * @param _twinId The ID of the digital twin.
     */
    function accessTwin(bytes32 _twinId) public payable {
        require(twins[_twinId].exists, "Digital twin does not exist");
        require(msg.value >= twins[_twinId].price, "Insufficient payment");
        require(msg.sender != twins[_twinId].owner, "Owner cannot purchase own twin");

        Twin storage twin = twins[_twinId];

        // Authorize accessor if not already authorized
        if (!twin.authorizedAccessors[msg.sender]) {
            twin.authorizedAccessors[msg.sender] = true;
        }

        // Transfer payment to the owner
        address owner = twin.owner;
        uint256 price = twin.price;
        (bool success, ) = owner.call{value: price}("");
        require(success, "Payment transfer failed");

        // Refund excess payment if any
        if (msg.value > price) {
            (bool refundSuccess, ) = msg.sender.call{value: msg.value - price}("");
            require(refundSuccess, "Refund transfer failed");
        }

        // Add custody log entry
        twin.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Twin accessed",
            timestamp: block.timestamp
        }));

        // Emit events
        emit TwinAccessed(_twinId, msg.sender, price);
        emit CustodyUpdated(_twinId, msg.sender, "Twin accessed");
    }

    /**
     * @dev Verifies a digital twin's state against a provided state hash.
     * @param _twinId The ID of the digital twin.
     * @param _stateHash The hash of the state to verify.
     * @return isValid True if the state hash matches the stored hash.
     */
    function verifyTwin(bytes32 _twinId, bytes32 _stateHash) 
        public 
        onlyAuthorized(_twinId) 
        returns (bool) 
    {
        require(twins[_twinId].exists, "Digital twin does not exist");
        require(_stateHash != bytes32(0), "State hash cannot be empty");

        Twin storage twin = twins[_twinId];
        bool isValid = (_stateHash == twin.stateHash);

        // Emit event
        emit TwinVerified(_twinId, msg.sender, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a digital twin.
     * @param _twinId The ID of the digital twin.
     * @return stateHash The hash of the current state.
     * @return creator The address of the twin creator.
     * @return description The description of the twin.
     * @return assetType The type of asset.
     * @return owner The owner of the twin record.
     * @return price The price for accessing the twin.
     * @return timestamp The timestamp of twin creation.
     * @return isLocked Whether the twin is locked.
     */
    function getTwin(bytes32 _twinId)
        public
        view
        onlyAuthorized(_twinId)
        returns (
            bytes32 stateHash,
            address creator,
            string memory description,
            string memory assetType,
            address owner,
            uint256 price,
            uint256 timestamp,
            bool isLocked
        )
    {
        require(twins[_twinId].exists, "Digital twin does not exist");
        Twin storage twin = twins[_twinId];
        return (
            twin.stateHash,
            twin.creator,
            twin.description,
            twin.assetType,
            twin.owner,
            twin.price,
            twin.timestamp,
            twin.isLocked
        );
    }

    /**
     * @dev Checks if an accessor is authorized for a digital twin.
     * @param _twinId The ID of the digital twin.
     * @param _accessor The address of the accessor.
     * @return True if the accessor is authorized, false otherwise.
     */
    function isAccessorAuthorized(bytes32 _twinId, address _accessor)
        public
        view
        onlyOwner(_twinId)
        returns (bool)
    {
        return twins[_twinId].authorizedAccessors[_accessor];
    }

    /**
     * @dev Retrieves the chain-of-custody log for a digital twin.
     * @param _twinId The ID of the digital twin.
     * @return custodians The array of custodian addresses.
     * @return actions The array of action descriptions.
     * @return timestamps The array of action timestamps.
     */
    function getCustodyLog(bytes32 _twinId)
        public
        view
        onlyAuthorized(_twinId)
        returns (
            address[] memory custodians,
            string[] memory actions,
            uint256[] memory timestamps
        )
    {
        require(twins[_twinId].exists, "Digital twin does not exist");
        Twin storage twin = twins[_twinId];
        uint256 logLength = twin.custodyLog.length;

        custodians = new address[](logLength);
        actions = new string[](logLength);
        timestamps = new uint256[](logLength);

        for (uint256 i = 0; i < logLength; i++) {
            custodians[i] = twin.custodyLog[i].custodian;
            actions[i] = twin.custodyLog[i].action;
            timestamps[i] = twin.custodyLog[i].timestamp;
        }

        return (custodians, actions, timestamps);
    }

    /**
     * @dev Retrieves the list of twin IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of twin IDs.
     */
    function getOwnerTwins(address _owner) public view returns (bytes32[] memory) {
        return ownerTwins[_owner];
    }
}