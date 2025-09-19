pragma solidity ^0.8.0;

// DirectlyAttachedStorage contract for managing DAS device metadata
contract DirectlyAttachedStorage {
    // Struct to store DAS device metadata
    struct DASDevice {
        string model; // Model of the DAS device (e.g., Samsung SSD 870 EVO)
        string serialNumber; // Unique serial number of the device
        string specsHash; // Hash of detailed specifications (e.g., IPFS hash)
        uint256 capacity; // Storage capacity in bytes
        address owner; // Owner of the device record
        uint256 registrationTime; // Timestamp of registration
        bool isVerified; // Verification status
        mapping(address => bool) authorizedViewers; // Access control for metadata
    }

    // Mapping from device ID to DASDevice struct
    mapping(uint256 => DASDevice) public devices;
    uint256 public deviceCount; // Counter for device IDs

    // Event emitted when a new DAS device is registered
    event DeviceRegistered(uint256 deviceId, string model, string serialNumber, address owner, uint256 registrationTime);
    // Event emitted when a device is verified
    event DeviceVerified(uint256 deviceId, address verifier);
    // Event emitted when access is granted
    event AccessGranted(uint256 deviceId, address viewer);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 deviceId, address viewer);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(uint256 deviceId, address newOwner);

    // Modifier to check if caller is the device owner
    modifier onlyOwner(uint256 _deviceId) {
        require(devices[_deviceId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if device exists
    modifier deviceExists(uint256 _deviceId) {
        require(_deviceId > 0 && _deviceId <= deviceCount, "Device does not exist");
        _;
    }

    // Function to register a new DAS device
    function registerDevice(
        string memory _model,
        string memory _serialNumber,
        string memory _specsHash,
        uint256 _capacity
    ) public {
        deviceCount++;
        DASDevice storage newDevice = devices[deviceCount];
        newDevice.model = _model;
        newDevice.serialNumber = _serialNumber;
        newDevice.specsHash = _specsHash;
        newDevice.capacity = _capacity;
        newDevice.owner = msg.sender;
        newDevice.registrationTime = block.timestamp;
        newDevice.isVerified = false; // Device starts unverified
        newDevice.authorizedViewers[msg.sender] = true; // Owner gets view access

        emit DeviceRegistered(deviceCount, _model, _serialNumber, msg.sender, block.timestamp);
    }

    // Function to verify a DAS device (e.g., by a manufacturer or authorized entity)
    function verifyDevice(uint256 _deviceId) public deviceExists(_deviceId) {
        // In production, restrict to a specific verifier role
        require(!devices[_deviceId].isVerified, "Device already verified");
        devices[_deviceId].isVerified = true;
        emit DeviceVerified(_deviceId, msg.sender);
    }

    // Function to grant view access to a device's metadata
    function grantAccess(uint256 _deviceId, address _viewer) public onlyOwner(_deviceId) deviceExists(_deviceId) {
        require(_viewer != address(0), "Invalid viewer address");
        devices[_deviceId].authorizedViewers[_viewer] = true;
        emit AccessGranted(_deviceId, _viewer);
    }

    // Function to revoke view access to a device's metadata
    function revokeAccess(uint256 _deviceId, address _viewer) public onlyOwner(_deviceId) deviceExists(_deviceId) {
        require(_viewer != devices[_deviceId].owner, "Cannot revoke owner's access");
        devices[_deviceId].authorizedViewers[_viewer] = false;
        emit AccessRevoked(_deviceId, _viewer);
    }

    // Function to check if a user has view access
    function hasAccess(uint256 _deviceId, address _viewer) public view deviceExists(_deviceId) returns (bool) {
        return devices[_deviceId].authorizedViewers[_viewer];
    }

    // Function to get device metadata (only for authorized viewers)
    function getDeviceMetadata(uint256 _deviceId) 
        public 
        view 
        deviceExists(_deviceId) 
        returns (
            string memory model,
            string memory serialNumber,
            string memory specsHash,
            uint256 capacity,
            address owner,
            uint256 registrationTime,
            bool isVerified
        ) 
    {
        require(devices[_deviceId].authorizedViewers[msg.sender], "Access denied");
        DASDevice storage device = devices[_deviceId];
        return (
            device.model,
            device.serialNumber,
            device.specsHash,
            device.capacity,
            device.owner,
            device.registrationTime,
            device.isVerified
        );
    }

    // Function to transfer ownership of a device
    function transferOwnership(uint256 _deviceId, address _newOwner) public onlyOwner(_deviceId) deviceExists(_deviceId) {
        require(_newOwner != address(0), "Invalid new owner address");
        devices[_deviceId].owner = _newOwner;
        devices[_deviceId].authorizedViewers[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_deviceId, _newOwner);
    }
}
