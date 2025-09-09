// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalMedia
 * @dev A smart contract for managing digital media assets with metadata, ownership, and licensing.
 * Supports registration, paid access, verification, and chain-of-custody tracking.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalMedia {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or accessor
        string action; // Description of the action (e.g., "Media created", "Access granted")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent a digital media asset
    struct MediaAsset {
        bytes32 mediaHash; // Keccak-256 hash of the media content (e.g., IPFS hash)
        string description; // Description of the media (e.g., "Digital artwork")
        string mediaType; // Type of media (e.g., "Image", "Video", "Audio")
        address owner; // Owner of the media asset
        uint256 price; // Price in wei for accessing the media
        address[] authorizedUsers; // List of addresses authorized to access the media
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of media creation
        bool exists; // Flag to check if media asset exists
    }

    // Mapping to store media assets by their unique ID
    mapping(bytes32 => MediaAsset) public mediaAssets;
    // Mapping to track media assets by owner
    mapping(address => bytes32[]) public ownerMedia;

    // Event emitted when a new media asset is created
    event MediaCreated(bytes32 indexed mediaId, bytes32 mediaHash, address indexed owner, string description, string mediaType);
    // Event emitted when a media asset is updated
    event MediaUpdated(bytes32 indexed mediaId, string newDescription, string newMediaType, uint256 newPrice);
    // Event emitted when media ownership is transferred
    event MediaTransferred(bytes32 indexed mediaId, address indexed newOwner);
    // Event emitted when a user is authorized to access a media asset
    event UserAuthorized(bytes32 indexed mediaId, address indexed user);
    // Event emitted when a media asset is accessed (purchased)
    event MediaAccessed(bytes32 indexed mediaId, address indexed user, uint256 price);
    // Event emitted when a media asset is verified
    event MediaVerified(bytes32 indexed mediaId, address indexed verifier, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed mediaId, address indexed custodian, string action);

    // Modifier to check if the caller is the owner of the media asset
    modifier onlyOwner(bytes32 mediaId) {
        require(mediaAssets[mediaId].owner == msg.sender, "Only the owner can perform this action");
        require(mediaAssets[mediaId].exists, "Media asset does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized user or owner
    modifier onlyAuthorized(bytes32 mediaId) {
        require(mediaAssets[mediaId].exists, "Media asset does not exist");
        bool isAuthorized = mediaAssets[mediaId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < mediaAssets[mediaId].authorizedUsers.length; i++) {
                if (mediaAssets[mediaId].authorizedUsers[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized users or owner can perform this action");
        _;
    }

    /**
     * @dev Creates a new digital media asset.
     * @param _mediaHash The Keccak-256 hash of the media content (e.g., IPFS hash).
     * @param _description The description of the media.
     * @param _mediaType The type of media (e.g., "Image", "Video", "Audio").
     * @param _price The price in wei for accessing the media.
     * @return mediaId The unique ID of the media asset.
     */
    function createMedia(
        bytes32 _mediaHash,
        string memory _description,
        string memory _mediaType,
        uint256 _price
    ) public returns (bytes32) {
        require(_mediaHash != bytes32(0), "Media hash cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(bytes(_mediaType).length > 0, "Media type cannot be empty");
        require(_price >= 0, "Price cannot be negative");

        // Generate a unique media ID
        bytes32 mediaId = keccak256(abi.encodePacked(_mediaHash, msg.sender, block.timestamp));
        
        // Ensure the media asset doesn't already exist
        require(!mediaAssets[mediaId].exists, "Media asset with this ID already exists");

        // Initialize the media asset
        MediaAsset storage newMedia = mediaAssets[mediaId];
        newMedia.mediaHash = _mediaHash;
        newMedia.description = _description;
        newMedia.mediaType = _mediaType;
        newMedia.owner = msg.sender;
        newMedia.price = _price;
        newMedia.timestamp = block.timestamp;
        newMedia.exists = true;

        // Initialize the custody log with the creation entry
        newMedia.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Media created",
            timestamp: block.timestamp
        }));

        // Add media ID to owner's list
        ownerMedia[msg.sender].push(mediaId);

        // Emit events for media creation and custody update
        emit MediaCreated(mediaId, _mediaHash, msg.sender, _description, _mediaType);
        emit CustodyUpdated(mediaId, msg.sender, "Media created");

        return mediaId;
    }

    /**
     * @dev Updates the description, media type, or price of an existing media asset.
     * @param _mediaId The ID of the media asset.
     * @param _newDescription The new description for the media.
     * @param _newMediaType The new media type.
     * @param _newPrice The new price in wei.
     */
    function updateMedia(
        bytes32 _mediaId,
        string memory _newDescription,
        string memory _newMediaType,
        uint256 _newPrice
    ) public onlyOwner(_mediaId) {
        require(bytes(_newDescription).length > 0, "Description cannot be empty");
        require(bytes(_newMediaType).length > 0, "Media type cannot be empty");
        require(_newPrice >= 0, "Price cannot be negative");

        mediaAssets[_mediaId].description = _newDescription;
        mediaAssets[_mediaId].mediaType = _newMediaType;
        mediaAssets[_mediaId].price = _newPrice;

        // Add custody log entry for update
        mediaAssets[_mediaId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Media updated",
            timestamp: block.timestamp
        }));

        // Emit events for media update and custody update
        emit MediaUpdated(_mediaId, _newDescription, _newMediaType, _newPrice);
        emit CustodyUpdated(_mediaId, msg.sender, "Media updated");
    }

    /**
     * @dev Transfers ownership of a media asset to a new address.
     * @param _mediaId The ID of the media asset.
     * @param _newOwner The address of the new owner.
     */
    function transferMediaOwnership(bytes32 _mediaId, address _newOwner) public onlyOwner(_mediaId) {
        require(_newOwner != address(0), "New owner address cannot be zero");
        require(_newOwner != mediaAssets[_mediaId].owner, "New owner must be different");

        // Update ownership
        mediaAssets[_mediaId].owner = _newOwner;

        // Add custody log entry for transfer
        mediaAssets[_mediaId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Ownership transferred to new owner",
            timestamp: block.timestamp
        }));

        // Update ownerMedia mappings
        bytes32[] storage ownerRecords = ownerMedia[msg.sender];
        for (uint256 i = 0; i < ownerRecords.length; i++) {
            if (ownerRecords[i] == _mediaId) {
                ownerRecords[i] = ownerRecords[ownerRecords.length - 1];
                ownerRecords.pop();
                break;
            }
        }
        ownerMedia[_newOwner].push(_mediaId);

        // Emit events for ownership transfer and custody update
        emit MediaTransferred(_mediaId, _newOwner);
        emit CustodyUpdated(_mediaId, msg.sender, "Ownership transferred to new owner");
    }

    /**
     * @dev Authorizes a user to access a media asset.
     * @param _mediaId The ID of the media asset.
     * @param _user The address of the user to authorize.
     */
    function authorizeUser(bytes32 _mediaId, address _user) public onlyOwner(_mediaId) {
        require(_user != address(0), "User address cannot be zero");
        // Check if user is already authorized
        for (uint256 i = 0; i < mediaAssets[_mediaId].authorizedUsers.length; i++) {
            require(mediaAssets[_mediaId].authorizedUsers[i] != _user, "User already authorized");
        }
        mediaAssets[_mediaId].authorizedUsers.push(_user);

        // Add custody log entry for authorization
        mediaAssets[_mediaId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "User authorized",
            timestamp: block.timestamp
        }));

        // Emit events for user authorization and custody update
        emit UserAuthorized(_mediaId, _user);
        emit CustodyUpdated(_mediaId, msg.sender, "User authorized");
    }

    /**
     * @dev Allows a user to access (purchase) a media asset by paying the specified price.
     * @param _mediaId The ID of the media asset.
     */
    function accessMedia(bytes32 _mediaId) public payable {
        require(mediaAssets[_mediaId].exists, "Media asset does not exist");
        require(msg.value >= mediaAssets[_mediaId].price, "Insufficient payment");
        require(msg.sender != mediaAssets[_mediaId].owner, "Owner cannot purchase own media");

        // Check if user is already authorized
        bool isAuthorized = false;
        for (uint256 i = 0; i < mediaAssets[_mediaId].authorizedUsers.length; i++) {
            if (mediaAssets[_mediaId].authorizedUsers[i] == msg.sender) {
                isAuthorized = true;
                break;
            }
        }
        if (!isAuthorized) {
            mediaAssets[_mediaId].authorizedUsers.push(msg.sender);
        }

        // Transfer payment to the owner
        address owner = mediaAssets[_mediaId].owner;
        uint256 price = mediaAssets[_mediaId].price;
        (bool success, ) = owner.call{value: price}("");
        require(success, "Payment transfer failed");

        // Refund excess payment if any
        if (msg.value > price) {
            (bool refundSuccess, ) = msg.sender.call{value: msg.value - price}("");
            require(refundSuccess, "Refund transfer failed");
        }

        // Add custody log entry for access
        mediaAssets[_mediaId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Media accessed",
            timestamp: block.timestamp
        }));

        // Emit events for media access and custody update
        emit MediaAccessed(_mediaId, msg.sender, price);
        emit CustodyUpdated(_mediaId, msg.sender, "Media accessed");
    }

    /**
     * @dev Verifies a media asset against provided media hash.
     * @param _mediaId The ID of the media asset.
     * @param _mediaHash The hash of the media content to verify.
     * @return isValid True if the media hash matches the stored hash, false otherwise.
     */
    function verifyMedia(bytes32 _mediaId, bytes32 _mediaHash) public onlyAuthorized(_mediaId) returns (bool) {
        require(mediaAssets[_mediaId].exists, "Media asset does not exist");
        require(_mediaHash != bytes32(0), "Media hash cannot be empty");

        bool isValid = (_mediaHash == mediaAssets[_mediaId].mediaHash);

        // Emit event for media verification
        emit MediaVerified(_mediaId, msg.sender, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a media asset.
     * @param _mediaId The ID of the media asset.
     * @return mediaHash The stored media hash.
     * @return description The description of the media.
     * @return mediaType The type of media.
     * @return owner The owner of the media asset.
     * @return price The price of the media.
     * @return timestamp The timestamp of media creation.
     */
    function getMedia(bytes32 _mediaId)
        public
        view
        onlyAuthorized(_mediaId)
        returns (
            bytes32 mediaHash,
            string memory description,
            string memory mediaType,
            address owner,
            uint256 price,
            uint256 timestamp
        )
    {
        require(mediaAssets[_mediaId].exists, "Media asset does not exist");
        MediaAsset storage media = mediaAssets[_mediaId];
        return (
            media.mediaHash,
            media.description,
            media.mediaType,
            media.owner,
            media.price,
            media.timestamp
        );
    }

    /**
     * @dev Retrieves the list of authorized users for a media asset.
     * @param _mediaId The ID of the media asset.
     * @return The array of authorized user addresses.
     */
    function getAuthorizedUsers(bytes32 _mediaId)
        public
        view
        onlyOwner(_mediaId)
        returns (address[] memory)
    {
        return mediaAssets[_mediaId].authorizedUsers;
    }

    /**
     * @dev Retrieves the chain-of-custody log for a media asset.
     * @param _mediaId The ID of the media asset.
     * @return custodians The array of custodian addresses.
     * @return actions The array of action descriptions.
     * @return timestamps The array of action timestamps.
     */
    function getCustodyLog(bytes32 _mediaId)
        public
        view
        onlyAuthorized(_mediaId)
        returns (
            address[] memory custodians,
            string[] memory actions,
            uint256[] memory timestamps
        )
    {
        require(mediaAssets[_mediaId].exists, "Media asset does not exist");
        MediaAsset storage media = mediaAssets[_mediaId];
        uint256 logLength = media.custodyLog.length;

        custodians = new address[](logLength);
        actions = new string[](logLength);
        timestamps = new uint256[](logLength);

        for (uint256 i = 0; i < logLength; i++) {
            custodians[i] = media.custodyLog[i].custodian;
            actions[i] = media.custodyLog[i].action;
            timestamps[i] = media.custodyLog[i].timestamp;
        }

        return (custodians, actions, timestamps);
    }

    /**
     * @dev Retrieves the list of media asset IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of media asset IDs.
     */
    function getOwnerMedia(address _owner) public view returns (bytes32[] memory) {
        return ownerMedia[_owner];
    }
}