pragma solidity ^0.8.0;

/**
 * @title DES
 * @dev A smart contract for managing encrypted data with access control, simulating DES-like functionality.
 * Requirements:
 * - Only the contract owner can authorize users.
 * - Only authorized users can store and retrieve encrypted data.
 * - Data is stored as a hash to simulate encryption (DES is not implemented directly due to gas costs).
 * - Events are emitted for transparency and auditability.
 */
contract DES {
    // Struct to represent encrypted data
    struct EncryptedData {
        bytes32 dataHash; // Hash of the data (simulating DES encryption output)
        address owner; // Address of the user who stored the data
        uint256 timestamp; // Timestamp of when the data was stored
    }

    // Mapping to store encrypted data by ID
    mapping(uint256 => EncryptedData) private dataStore;

    // Mapping to store authorized users
    mapping(address => bool) private authorizedUsers;

    // Contract owner
    address private contractOwner;

    // Counter for data IDs
    uint256 private dataIdCounter;

    // Event for data storage
    event DataStored(uint256 indexed dataId, bytes32 dataHash, address indexed owner, uint256 timestamp);

    // Event for data retrieval
    event DataRetrieved(uint256 indexed dataId, bytes32 dataHash, address indexed requester);

    // Event for user authorization changes
    event UserAuthorizationChanged(address indexed user, bool authorized);

    /**
     * @dev Constructor to set the contract owner.
     * Requirement: Contract owner cannot be the zero address.
     */
    constructor() {
        require(msg.sender != address(0), "Contract owner cannot be the zero address");
        contractOwner = msg.sender;
        authorizedUsers[msg.sender] = true;
        emit UserAuthorizationChanged(msg.sender, true);
    }

    /**
     * @dev Modifier to restrict functions to the contract owner.
     * Requirement: Only the contract owner can authorize users.
     */
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the contract owner");
        _;
    }

    /**
     * @dev Modifier to restrict functions to authorized users.
     * Requirement: Only authorized users can store or retrieve data.
     */
    modifier onlyAuthorized() {
        require(authorizedUsers[msg.sender], "Caller is not authorized");
        _;
    }

    /**
     * @dev Authorizes or deauthorizes a user.
     * @param _user The address to authorize or deauthorize.
     * @param _authorized True to authorize, false to deauthorize.
     * Requirement: Only the contract owner can call this function.
     */
    function setUserAuthorization(address _user, bool _authorized) public onlyOwner {
        require(_user != address(0), "User cannot be the zero address");
        authorizedUsers[_user] = _authorized;
        emit UserAuthorizationChanged(_user, _authorized);
    }

    /**
     * @dev Stores encrypted data (simulated as a hash).
     * @param _data The data to be hashed and stored.
     * Requirement: Only authorized users can store data.
     * Requirement: Data cannot be empty.
     * @return dataId The ID assigned to the stored data.
     */
    function storeData(bytes memory _data) public onlyAuthorized returns (uint256) {
        require(_data.length > 0, "Data cannot be empty");
        bytes32 dataHash = keccak256(_data); // Simulate DES encryption with a hash
        uint256 dataId = dataIdCounter++;
        
        dataStore[dataId] = EncryptedData({
            dataHash: dataHash,
            owner: msg.sender,
            timestamp: block.timestamp
        });

        emit DataStored(dataId, dataHash, msg.sender, block.timestamp);
        return dataId;
    }

    /**
     * @dev Retrieves encrypted data by ID.
     * @param _dataId The ID of the stored data.
     * @return dataHash The hash of the stored data.
     * Requirement: Only authorized users can retrieve data.
     * Requirement: Data ID must exist.
     */
    function retrieveData(uint256 _dataId) public onlyAuthorized returns (bytes32) {
        require(dataStore[_dataId].owner != address(0), "Data does not exist");
        emit DataRetrieved(_dataId, dataStore[_dataId].dataHash, msg.sender);
        return dataStore[_dataId].dataHash;
    }

    /**
     * @dev Verifies if the provided data matches the stored data hash.
     * @param _dataId The ID of the stored data.
     * @param _data The data to verify against the stored hash.
     * @return bool True if the data matches the stored hash.
     * Requirement: Only authorized users can verify data.
     * Requirement: Data ID must exist.
     */
    function verifyData(uint256 _dataId, bytes memory _data) public view onlyAuthorized returns (bool) {
        require(dataStore[_dataId].owner != address(0), "Data does not exist");
        return keccak256(_data) == dataStore[_dataId].dataHash;
    }

    /**
     * @dev Returns the contract owner.
     * @return address The address of the contract owner.
     */
    function getContractOwner() public view returns (address) {
        return contractOwner;
    }

    /**
     * @dev Checks if a user is authorized.
     * @param _user The address to check.
     * @return bool True if the user is authorized.
     */
    function isAuthorized(address _user) public view returns (bool) {
        return authorizedUsers[_user];
    }
}