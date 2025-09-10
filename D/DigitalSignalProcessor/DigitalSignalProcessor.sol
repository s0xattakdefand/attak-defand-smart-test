// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalSignalProcessor
 * @dev A smart contract for managing digital signal metadata with versioning, access control, and paid access.
 * Supports signal registration, verification, and chain-of-custody tracking.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalSignalProcessor {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or accessor
        string action; // Description of the action (e.g., "Signal created", "Signal accessed")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent a signal version
    struct SignalVersion {
        bytes32 signalHash; // Keccak-256 hash of the signal data (e.g., processed audio or sensor data)
        string description; // Description of the signal version
        string processingInstructions; // Instructions for processing (e.g., FFT parameters)
        uint256 versionNumber; // Version number of the signal
        uint256 timestamp; // Timestamp of version creation
    }

    // Struct to represent a digital signal
    struct Signal {
        string signalName; // Name of the signal
        string signalType; // Type of signal (e.g., "Audio", "Video", "Sensor")
        address owner; // Owner of the signal
        uint256 price; // Price in wei for accessing the signal
        mapping(address => bool) authorizedUsers; // Mapping of authorized users
        SignalVersion[] versions; // Array of signal versions
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of signal creation
        bool exists; // Flag to check if signal exists
        bool isLocked; // Flag to lock signal from further modifications
    }

    // Mapping to store signals by their unique ID
    mapping(bytes32 => Signal) public signals;
    // Mapping to track signals by owner
    mapping(address => bytes32[]) public ownerSignals;

    // Role definitions
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant PROCESSOR_ROLE = keccak256("PROCESSOR_ROLE");

    // Mapping to track roles for addresses
    mapping(address => mapping(bytes32 => bool)) public roles;

    // Event emitted when a new signal is created
    event SignalCreated(bytes32 indexed signalId, string signalName, address indexed owner, string signalType, bytes32 initialSignalHash);
    // Event emitted when a new signal version is added
    event SignalVersionAdded(bytes32 indexed signalId, uint256 versionNumber, bytes32 signalHash, string description);
    // Event emitted when a signal is updated
    event SignalUpdated(bytes32 indexed signalId, string newSignalName, string newSignalType, uint256 newPrice);
    // Event emitted when a signal is locked
    event SignalLocked(bytes32 indexed signalId, address indexed owner);
    // Event emitted when signal ownership is transferred
    event SignalTransferred(bytes32 indexed signalId, address indexed newOwner);
    // Event emitted when a user is authorized
    event UserAuthorized(bytes32 indexed signalId, address indexed user);
    // Event emitted when a signal is accessed (purchased)
    event SignalAccessed(bytes32 indexed signalId, address indexed user, uint256 price);
    // Event emitted when a signal version is verified
    event SignalVerified(bytes32 indexed signalId, uint256 versionNumber, address indexed verifier, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed signalId, address indexed custodian, string action);
    // Event emitted when a role is assigned
    event RoleAssigned(address indexed user, bytes32 indexed role);

    // Modifier to check if the caller has a specific role
    modifier onlyRole(bytes32 role) {
        require(roles[msg.sender][role], "Caller does not have the required role");
        _;
    }

    // Modifier to check if the caller is the owner of the signal
    modifier onlyOwner(bytes32 signalId) {
        require(signals[signalId].owner == msg.sender, "Only the owner can perform this action");
        require(signals[signalId].exists, "Signal does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized user or owner
    modifier onlyAuthorized(bytes32 signalId) {
        require(signals[signalId].exists, "Signal does not exist");
        require(
            signals[signalId].owner == msg.sender || 
            signals[signalId].authorizedUsers[msg.sender] || 
            roles[msg.sender][PROCESSOR_ROLE],
            "Only authorized users, owner, or processors can perform this action"
        );
        _;
    }

    // Modifier to check if the signal is not locked
    modifier notLocked(bytes32 signalId) {
        require(!signals[signalId].isLocked, "Signal is locked and cannot be modified");
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
     * @param _role The role to assign (ADMIN_ROLE or PROCESSOR_ROLE).
     */
    function assignRole(address _user, bytes32 _role) public onlyRole(ADMIN_ROLE) {
        require(_user != address(0), "User address cannot be zero");
        require(_role == ADMIN_ROLE || _role == PROCESSOR_ROLE, "Invalid role");
        roles[_user][_role] = true;
        emit RoleAssigned(_user, _role);
    }

    /**
     * @dev Creates a new digital signal with an initial version.
     * @param _signalHash The Keccak-256 hash of the initial signal data.
     * @param _signalName The name of the signal.
     * @param _signalType The type of signal (e.g., "Audio", "Video", "Sensor").
     * @param _description The description of the initial signal version.
     * @param _processingInstructions Instructions for processing (e.g., FFT parameters).
     * @param _price The price in wei for accessing the signal.
     * @return signalId The unique ID of the signal.
     */
    function createSignal(
        bytes32 _signalHash,
        string memory _signalName,
        string memory _signalType,
        string memory _description,
        string memory _processingInstructions,
        uint256 _price
    ) public returns (bytes32) {
        require(_signalHash != bytes32(0), "Signal hash cannot be empty");
        require(bytes(_signalName).length > 0, "Signal name cannot be empty");
        require(bytes(_signalType).length > 0, "Signal type cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(_price >= 0, "Price cannot be negative");

        // Generate a unique signal ID
        bytes32 signalId = keccak256(abi.encodePacked(_signalHash, msg.sender, block.timestamp));
        
        // Ensure the signal doesn't already exist
        require(!signals[signalId].exists, "Signal with this ID already exists");

        // Initialize the signal
        Signal storage newSignal = signals[signalId];
        newSignal.signalName = _signalName;
        newSignal.signalType = _signalType;
        newSignal.owner = msg.sender;
        newSignal.price = _price;
        newSignal.timestamp = block.timestamp;
        newSignal.exists = true;
        newSignal.isLocked = false;

        // Add initial version
        newSignal.versions.push(SignalVersion({
            signalHash: _signalHash,
            description: _description,
            processingInstructions: _processingInstructions,
            versionNumber: 1,
            timestamp: block.timestamp
        }));

        // Initialize the custody log
        newSignal.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Signal created",
            timestamp: block.timestamp
        }));

        // Add signal ID to owner's list
        ownerSignals[msg.sender].push(signalId);

        // Emit events
        emit SignalCreated(signalId, _signalName, msg.sender, _signalType, _signalHash);
        emit SignalVersionAdded(signalId, 1, _signalHash, _description);
        emit CustodyUpdated(signalId, msg.sender, "Signal created");

        return signalId;
    }

    /**
     * @dev Adds a new version to an existing signal.
     * @param _signalId The ID of the signal.
     * @param _signalHash The Keccak-256 hash of the new signal data.
     * @param _description The description of the new signal version.
     * @param _processingInstructions New processing instructions.
     */
    function addSignalVersion(
        bytes32 _signalId,
        bytes32 _signalHash,
        string memory _description,
        string memory _processingInstructions
    ) public onlyOwner(_signalId) notLocked(_signalId) {
        require(_signalHash != bytes32(0), "Signal hash cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        Signal storage signal = signals[_signalId];
        uint256 newVersionNumber = signal.versions.length + 1;

        // Add new version
        signal.versions.push(SignalVersion({
            signalHash: _signalHash,
            description: _description,
            processingInstructions: _processingInstructions,
            versionNumber: newVersionNumber,
            timestamp: block.timestamp
        }));

        // Add custody log entry
        signal.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "New signal version added",
            timestamp: block.timestamp
        }));

        // Emit events
        emit SignalVersionAdded(_signalId, newVersionNumber, _signalHash, _description);
        emit CustodyUpdated(_signalId, msg.sender, "New signal version added");
    }

    /**
     * @dev Updates the name, type, or price of an existing signal.
     * @param _signalId The ID of the signal.
     * @param _newSignalName The new name for the signal.
     * @param _newSignalType The new signal type.
     * @param _newPrice The new price in wei.
     */
    function updateSignal(
        bytes32 _signalId,
        string memory _newSignalName,
        string memory _newSignalType,
        uint256 _newPrice
    ) public onlyOwner(_signalId) notLocked(_signalId) {
        require(bytes(_newSignalName).length > 0, "Signal name cannot be empty");
        require(bytes(_newSignalType).length > 0, "Signal type cannot be empty");
        require(_newPrice >= 0, "Price cannot be negative");

        Signal storage signal = signals[_signalId];
        signal.signalName = _newSignalName;
        signal.signalType = _newSignalType;
        signal.price = _newPrice;

        // Add custody log entry
        signal.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Signal updated",
            timestamp: block.timestamp
        }));

        // Emit events
        emit SignalUpdated(_signalId, _newSignalName, _newSignalType, _newPrice);
        emit CustodyUpdated(_signalId, msg.sender, "Signal updated");
    }

    /**
     * @dev Locks a signal to prevent further modifications.
     * @param _signalId The ID of the signal.
     */
    function lockSignal(bytes32 _signalId) public onlyOwner(_signalId) notLocked(_signalId) {
        signals[_signalId].isLocked = true;

        // Add custody log entry
        signals[_signalId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Signal locked",
            timestamp: block.timestamp
        }));

        // Emit events
        emit SignalLocked(_signalId, msg.sender);
        emit CustodyUpdated(_signalId, msg.sender, "Signal locked");
    }

    /**
     * @dev Transfers ownership of a signal to a new address.
     * @param _signalId The ID of the signal.
     * @param _newOwner The address of the new owner.
     */
    function transferSignalOwnership(bytes32 _signalId, address _newOwner) public onlyOwner(_signalId) notLocked(_signalId) {
        require(_newOwner != address(0), "New owner address cannot be zero");
        require(_newOwner != signals[_signalId].owner, "New owner must be different");

        // Update ownership
        signals[_signalId].owner = _newOwner;

        // Add custody log entry
        signals[_signalId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Ownership transferred to new owner",
            timestamp: block.timestamp
        }));

        // Update ownerSignals mappings
        bytes32[] storage ownerRecords = ownerSignals[msg.sender];
        for (uint256 i = 0; i < ownerRecords.length; i++) {
            if (ownerRecords[i] == _signalId) {
                ownerRecords[i] = ownerRecords[ownerRecords.length - 1];
                ownerRecords.pop();
                break;
            }
        }
        ownerSignals[_newOwner].push(_signalId);

        // Emit events
        emit SignalTransferred(_signalId, _newOwner);
        emit CustodyUpdated(_signalId, msg.sender, "Ownership transferred to new owner");
    }

    /**
     * @dev Authorizes a user to access a signal.
     * @param _signalId The ID of the signal.
     * @param _user The address of the user to authorize.
     */
    function authorizeUser(bytes32 _signalId, address _user) public onlyOwner(_signalId) notLocked(_signalId) {
        require(_user != address(0), "User address cannot be zero");
        require(!signals[_signalId].authorizedUsers[_user], "User already authorized");

        signals[_signalId].authorizedUsers[_user] = true;

        // Add custody log entry
        signals[_signalId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "User authorized",
            timestamp: block.timestamp
        }));

        // Emit events
        emit UserAuthorized(_signalId, _user);
        emit CustodyUpdated(_signalId, msg.sender, "User authorized");
    }

    /**
     * @dev Allows a user to access (purchase) a signal by paying the specified price.
     * @param _signalId The ID of the signal.
     */
    function accessSignal(bytes32 _signalId) public payable {
        require(signals[_signalId].exists, "Signal does not exist");
        require(msg.value >= signals[_signalId].price, "Insufficient payment");
        require(msg.sender != signals[_signalId].owner, "Owner cannot purchase own signal");

        Signal storage signal = signals[_signalId];

        // Authorize user if not already authorized
        if (!signal.authorizedUsers[msg.sender]) {
            signal.authorizedUsers[msg.sender] = true;
        }

        // Transfer payment to the owner
        address owner = signal.owner;
        uint256 price = signal.price;
        (bool success, ) = owner.call{value: price}("");
        require(success, "Payment transfer failed");

        // Refund excess payment if any
        if (msg.value > price) {
            (bool refundSuccess, ) = msg.sender.call{value: msg.value - price}("");
            require(refundSuccess, "Refund transfer failed");
        }

        // Add custody log entry
        signal.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Signal accessed",
            timestamp: block.timestamp
        }));

        // Emit events
        emit SignalAccessed(_signalId, msg.sender, price);
        emit CustodyUpdated(_signalId, msg.sender, "Signal accessed");
    }

    /**
     * @dev Verifies a signal version against provided signal data hash.
     * @param _signalId The ID of the signal.
     * @param _versionNumber The version number to verify.
     * @param _signalHash The hash of the signal data to verify.
     * @return isValid True if the signal hash matches the stored hash for the version.
     */
    function verifySignal(bytes32 _signalId, uint256 _versionNumber, bytes32 _signalHash) 
        public 
        onlyAuthorized(_signalId) 
        returns (bool) 
    {
        require(signals[_signalId].exists, "Signal does not exist");
        require(_versionNumber > 0 && _versionNumber <= signals[_signalId].versions.length, "Invalid version number");
        require(_signalHash != bytes32(0), "Signal hash cannot be empty");

        SignalVersion storage version = signals[_signalId].versions[_versionNumber - 1];
        bool isValid = (_signalHash == version.signalHash);

        // Emit event
        emit SignalVerified(_signalId, _versionNumber, msg.sender, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a signal.
     * @param _signalId The ID of the signal.
     * @return signalName The name of the signal.
     * @return signalType The type of signal.
     * @return owner The owner of the signal.
     * @return price The price for accessing the signal.
     * @return timestamp The timestamp of signal creation.
     * @return isLocked Whether the signal is locked.
     */
    function getSignal(bytes32 _signalId)
        public
        view
        onlyAuthorized(_signalId)
        returns (
            string memory signalName,
            string memory signalType,
            address owner,
            uint256 price,
            uint256 timestamp,
            bool isLocked
        )
    {
        require(signals[_signalId].exists, "Signal does not exist");
        Signal storage signal = signals[_signalId];
        return (
            signal.signalName,
            signal.signalType,
            signal.owner,
            signal.price,
            signal.timestamp,
            signal.isLocked
        );
    }

    /**
     * @dev Retrieves the details of a specific signal version.
     * @param _signalId The ID of the signal.
     * @param _versionNumber The version number to retrieve.
     * @return signalHash The hash of the signal data.
     * @return description The description of the version.
     * @return processingInstructions The processing instructions.
     * @return versionNumber The version number.
     * @return timestamp The timestamp of version creation.
     */
    function getSignalVersion(bytes32 _signalId, uint256 _versionNumber)
        public
        view
        onlyAuthorized(_signalId)
        returns (
            bytes32 signalHash,
            string memory description,
            string memory processingInstructions,
            uint256 versionNumber,
            uint256 timestamp
        )
    {
        require(signals[_signalId].exists, "Signal does not exist");
        require(_versionNumber > 0 && _versionNumber <= signals[_signalId].versions.length, "Invalid version number");
        SignalVersion storage version = signals[_signalId].versions[_versionNumber - 1];
        return (
            version.signalHash,
            version.description,
            version.processingInstructions,
            version.versionNumber,
            version.timestamp
        );
    }

    /**
     * @dev Checks if a user is authorized for a signal.
     * @param _signalId The ID of the signal.
     * @param _user The address of the user.
     * @return True if the user is authorized, false otherwise.
     */
    function isUserAuthorized(bytes32 _signalId, address _user)
        public
        view
        onlyOwner(_signalId)
        returns (bool)
    {
        return signals[_signalId].authorizedUsers[_user];
    }

    /**
     * @dev Retrieves the chain-of-custody log for a signal.
     * @param _signalId The ID of the signal.
     * @return custodians The array of custodian addresses.
     * @return actions The array of action descriptions.
     * @return timestamps The array of action timestamps.
     */
    function getCustodyLog(bytes32 _signalId)
        public
        view
        onlyAuthorized(_signalId)
        returns (
            address[] memory custodians,
            string[] memory actions,
            uint256[] memory timestamps
        )
    {
        require(signals[_signalId].exists, "Signal does not exist");
        Signal storage signal = signals[_signalId];
        uint256 logLength = signal.custodyLog.length;

        custodians = new address[](logLength);
        actions = new string[](logLength);
        timestamps = new uint256[](logLength);

        for (uint256 i = 0; i < logLength; i++) {
            custodians[i] = signal.custodyLog[i].custodian;
            actions[i] = signal.custodyLog[i].action;
            timestamps[i] = signal.custodyLog[i].timestamp;
        }

        return (custodians, actions, timestamps);
    }

    /**
     * @dev Retrieves the list of signal IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of signal IDs.
     */
    function getOwnerSignals(address _owner) public view returns (bytes32[] memory) {
        return ownerSignals[_owner];
    }
}