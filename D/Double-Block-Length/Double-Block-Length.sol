pragma solidity ^0.8.0;

// DNP3 contract for managing DNP3 device registrations and data points
contract DNP3 {
    // Struct to store DNP3 device metadata
    struct DNP3Device {
        string deviceId; // Unique identifier for the DNP3 device (e.g., RTU serial)
        string location; // Physical location of the device
        string configHash; // Hash of device configuration (e.g., IPFS hash)
        address owner; // Owner of the device record
        uint256 registrationTime; // Timestamp of registration
        bool isVerified; // Verification status
        mapping(address => bool) authorizedOperators; // Access control for operations
    }

    // Struct to store data point (e.g., analog input, binary output)
    struct DataPoint {
        string pointType; // Type: "analog", "binary", "counter", etc.
        uint16 index; // Point index
        string valueHash; // Hash of the current value or data
        uint256 timestamp; // Last update timestamp
        bool isActive; // Status of the point
    }

    // Mapping from device ID to DNP3Device struct
    mapping(string => DNP3Device) public devices;
    mapping(string => mapping(uint16 => DataPoint)) public dataPoints; // Device -> Index -> DataPoint

    // Event emitted when a new DNP3 device is registered
    event DeviceRegistered(string deviceId, string location, address owner, uint256 registrationTime);
    // Event emitted when a device is verified
    event DeviceVerified(string deviceId, address verifier);
    // Event emitted when a data point is updated
    event DataPointUpdated(string deviceId, uint16 index, string pointType, string valueHash, uint256 timestamp);
    // Event emitted when access is granted
    event AccessGranted(string deviceId, address operator);
    // Event emitted when access is revoked
    event AccessRevoked(string deviceId, address operator);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(string deviceId, address newOwner);

    // Modifier to check if caller is the device owner
    modifier onlyOwner(string memory _deviceId) {
        require(devices[_deviceId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if device exists
    modifier deviceExists(string memory _deviceId) {
        require(bytes(devices[_deviceId].deviceId).length > 0, "Device does not exist");
        _;
    }

    // Function to register a new DNP3 device
    function registerDevice(string memory _deviceId, string memory _location, string memory _configHash) public {
        require(bytes(devices[_deviceId].deviceId).length == 0, "Device already registered");
        devices[_deviceId].deviceId = _deviceId;
        devices[_deviceId].location = _location;
        devices[_deviceId].configHash = _configHash;
        devices[_deviceId].owner = msg.sender;
        devices[_deviceId].registrationTime = block.timestamp;
        devices[_deviceId].isVerified = false;
        devices[_deviceId].authorizedOperators[msg.sender] = true; // Owner gets access

        emit DeviceRegistered(_deviceId, _location, msg.sender, block.timestamp);
    }

    // Function to verify a DNP3 device (e.g., by an authorized entity)
    function verifyDevice(string memory _deviceId) public deviceExists(_deviceId) {
        // In production, restrict to a specific verifier role
        require(!devices[_deviceId].isVerified, "Device already verified");
        devices[_deviceId].isVerified = true;
        emit DeviceVerified(_deviceId, msg.sender);
    }

    // Function to update a data point for a device
    function updateDataPoint(string memory _deviceId, uint16 _index, string memory _pointType, string memory _valueHash) public deviceExists(_deviceId) {
        require(devices[_deviceId].authorizedOperators[msg.sender], "Not authorized to update data points");
        dataPoints[_deviceId][_index].pointType = _pointType;
        dataPoints[_deviceId][_index].valueHash = _valueHash;
        dataPoints[_deviceId][_index].timestamp = block.timestamp;
        dataPoints[_deviceId][_index].isActive = true;

        emit DataPointUpdated(_deviceId, _index, _pointType, _valueHash, block.timestamp);
    }

    // Function to grant operational access to a device
    function grantAccess(string memory _deviceId, address _operator) public onlyOwner(_deviceId) deviceExists(_deviceId) {
        require(_operator != address(0), "Invalid operator address");
        devices[_deviceId].authorizedOperators[_operator] = true;
        emit AccessGranted(_deviceId, _operator);
    }

    // Function to revoke operational access to a device
    function revokeAccess(string memory _deviceId, address _operator) public onlyOwner(_deviceId) deviceExists(_deviceId) {
        require(_operator != devices[_deviceId].owner, "Cannot revoke owner's access");
        devices[_deviceId].authorizedOperators[_operator] = false;
        emit AccessRevoked(_deviceId, _operator);
    }

    // Function to check if a user has operational access
    function hasAccess(string memory _deviceId, address _operator) public view deviceExists(_deviceId) returns (bool) {
        return devices[_deviceId].authorizedOperators[_operator];
    }

    // Function to get device metadata (only for authorized operators)
    function getDeviceMetadata(string memory _deviceId) 
        public 
        view 
        deviceExists(_deviceId) 
        returns (string memory location, string memory configHash, address owner, uint256 registrationTime, bool isVerified) 
    {
        require(devices[_deviceId].authorizedOperators[msg.sender], "Access denied");
        DNP3Device storage device = devices[_deviceId];
        return (device.location, device.configHash, device.owner, device.registrationTime, device.isVerified);
    }

    // Function to get data point info (only for authorized operators)
    function getDataPoint(string memory _deviceId, uint16 _index) 
        public 
        view 
        deviceExists(_deviceId) 
        returns (string memory pointType, string memory valueHash, uint256 timestamp, bool isActive) 
    {
        require(devices[_deviceId].authorizedOperators[msg.sender], "Access denied");
        DataPoint storage point = dataPoints[_deviceId][_index];
        return (point.pointType, point.valueHash, point.timestamp, point.isActive);
    }

    // Function to transfer ownership of a device
    function transferOwnership(string memory _deviceId, address _newOwner) public onlyOwner(_deviceId) deviceExists(_deviceId) {
        require(_newOwner != address(0), "Invalid new owner address");
        devices[_deviceId].owner = _newOwner;
        devices[_deviceId].authorizedOperators[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_deviceId, _newOwner);
    }
}
