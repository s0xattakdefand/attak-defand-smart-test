pragma solidity ^0.8.0;

// DisciplinedOscillator contract for managing disciplined oscillator devices
contract DisciplinedOscillator {
    // Struct to store disciplined oscillator metadata
    struct Oscillator {
        string model; // Model of the oscillator (e.g., GPSDO-100)
        string serialNumber; // Unique serial number
        string referenceType; // Reference type (e.g., GPS, GNSS)
        string specsHash; // Hash of specifications (e.g., IPFS hash for accuracy data)
        address owner; // Owner of the device record
        uint256 registrationTime; // Timestamp of registration
        bool isVerified; // Verification status
        mapping(address => bool) authorizedViewers; // Access control for metadata
    }

    // Mapping from device ID to Oscillator struct
    mapping(uint256 => Oscillator) public oscillators;
    uint256 public oscillatorCount; // Counter for device IDs

    // Event emitted when a new oscillator is registered
    event OscillatorRegistered(uint256 oscillatorId, string model, string serialNumber, address owner, uint256 registrationTime);
    // Event emitted when an oscillator is verified
    event OscillatorVerified(uint256 oscillatorId, address verifier);
    // Event emitted when access is granted
    event AccessGranted(uint256 oscillatorId, address viewer);
    // Event emitted when access is revoked
    event AccessRevoked(uint256 oscillatorId, address viewer);
    // Event emitted when ownership is transferred
    event OwnershipTransferred(uint256 oscillatorId, address newOwner);

    // Modifier to check if caller is the oscillator owner
    modifier onlyOwner(uint256 _oscillatorId) {
        require(oscillators[_oscillatorId].owner == msg.sender, "Only the owner can perform this action");
        _;
    }

    // Modifier to check if oscillator exists
    modifier oscillatorExists(uint256 _oscillatorId) {
        require(_oscillatorId > 0 && _oscillatorId <= oscillatorCount, "Oscillator does not exist");
        _;
    }

    // Function to register a new disciplined oscillator
    function registerOscillator(
        string memory _model,
        string memory _serialNumber,
        string memory _referenceType,
        string memory _specsHash
    ) public {
        oscillatorCount++;
        Oscillator storage newOscillator = oscillators[oscillatorCount];
        newOscillator.model = _model;
        newOscillator.serialNumber = _serialNumber;
        newOscillator.referenceType = _referenceType;
        newOscillator.specsHash = _specsHash;
        newOscillator.owner = msg.sender;
        newOscillator.registrationTime = block.timestamp;
        newOscillator.isVerified = false; // Starts unverified
        newOscillator.authorizedViewers[msg.sender] = true; // Owner gets access

        emit OscillatorRegistered(oscillatorCount, _model, _serialNumber, msg.sender, block.timestamp);
    }

    // Function to verify an oscillator (e.g., by manufacturer or calibrator)
    function verifyOscillator(uint256 _oscillatorId) public oscillatorExists(_oscillatorId) {
        // In production, restrict to specific verifier role
        require(!oscillators[_oscillatorId].isVerified, "Oscillator already verified");
        oscillators[_oscillatorId].isVerified = true;
        emit OscillatorVerified(_oscillatorId, msg.sender);
    }

    // Function to grant view access to oscillator metadata
    function grantAccess(uint256 _oscillatorId, address _viewer) public onlyOwner(_oscillatorId) oscillatorExists(_oscillatorId) {
        require(_viewer != address(0), "Invalid viewer address");
        oscillators[_oscillatorId].authorizedViewers[_viewer] = true;
        emit AccessGranted(_oscillatorId, _viewer);
    }

    // Function to revoke view access to oscillator metadata
    function revokeAccess(uint256 _oscillatorId, address _viewer) public onlyOwner(_oscillatorId) oscillatorExists(_oscillatorId) {
        require(_viewer != oscillators[_oscillatorId].owner, "Cannot revoke owner's access");
        oscillators[_oscillatorId].authorizedViewers[_viewer] = false;
        emit AccessRevoked(_oscillatorId, _viewer);
    }

    // Function to check if a user has view access
    function hasAccess(uint256 _oscillatorId, address _viewer) public view oscillatorExists(_oscillatorId) returns (bool) {
        return oscillators[_oscillatorId].authorizedViewers[_viewer];
    }

    // Function to get oscillator metadata (only for authorized viewers)
    function getOscillatorMetadata(uint256 _oscillatorId) 
        public 
        view 
        oscillatorExists(_oscillatorId) 
        returns (
            string memory model,
            string memory serialNumber,
            string memory referenceType,
            string memory specsHash,
            address owner,
            uint256 registrationTime,
            bool isVerified
        ) 
    {
        require(oscillators[_oscillatorId].authorizedViewers[msg.sender], "Access denied");
        Oscillator storage oscillator = oscillators[_oscillatorId];
        return (
            oscillator.model,
            oscillator.serialNumber,
            oscillator.referenceType,
            oscillator.specsHash,
            oscillator.owner,
            oscillator.registrationTime,
            oscillator.isVerified
        );
    }

    // Function to transfer ownership of an oscillator
    function transferOwnership(uint256 _oscillatorId, address _newOwner) public onlyOwner(_oscillatorId) oscillatorExists(_oscillatorId) {
        require(_newOwner != address(0), "Invalid new owner address");
        oscillators[_oscillatorId].owner = _newOwner;
        oscillators[_oscillatorId].authorizedViewers[_newOwner] = true; // Grant access to new owner
        emit OwnershipTransferred(_oscillatorId, _newOwner);
    }
}
