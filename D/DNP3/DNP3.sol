// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Decentralized Network Protocol 3 (DNP3) inspired smart contract
contract DNP3 {
    // Struct to represent an outstation (device)
    struct Outstation {
        address deviceAddress; // Ethereum address of the outstation
        bytes publicKey; // Public key for authentication
        bool registered; // Whether the outstation is registered
        mapping(uint256 => uint256) analogInputs; // Analog input data points
        mapping(uint256 => bool) binaryOutputs; // Binary output states (e.g., CROB)
    }

    // Mapping to store outstations by ID
    mapping(uint256 => Outstation) public outstations;

    // Master station (contract owner)
    address public masterStation;

    // Counter for outstation IDs
    uint256 public outstationCount;

    // Event emitted when an outstation is registered
    event OutstationRegistered(uint256 indexed outstationId, address deviceAddress, bytes publicKey);

    // Event emitted when a control command is issued
    event ControlCommandIssued(uint256 indexed outstationId, uint256 pointIndex, bool value);

    // Event emitted when a data point is updated
    event DataPointUpdated(uint256 indexed outstationId, uint256 pointIndex, uint256 value);

    // Event emitted when a command is verified
    event CommandVerified(uint256 indexed outstationId, bytes32 commandHash, bool isValid);

    // Modifier to restrict actions to the master station
    modifier onlyMasterStation() {
        require(msg.sender == masterStation, "Only master station can call this function");
        _;
    }

    // Modifier to check if outstation is registered
    modifier onlyRegisteredOutstation(uint256 outstationId) {
        require(outstations[outstationId].registered, "Outstation not registered");
        _;
    }

    // Constructor to initialize the master station
    constructor() {
        masterStation = msg.sender;
        outstationCount = 0;
    }

    // Register a new outstation
    function registerOutstation(address deviceAddress, bytes memory publicKey) 
        external 
        onlyMasterStation 
        returns (uint256) 
    {
        require(deviceAddress != address(0), "Invalid device address");
        require(publicKey.length > 0, "Public key cannot be empty");

        outstationCount++;
        Outstation storage outstation = outstations[outstationCount];
        outstation.deviceAddress = deviceAddress;
        outstation.publicKey = publicKey;
        outstation.registered = true;

        emit OutstationRegistered(outstationCount, deviceAddress, publicKey);
        return outstationCount;
    }

    // Issue a binary output command (e.g., CROB)
    function issueControlCommand(
        uint256 outstationId,
        uint256 pointIndex,
        bool value,
        bytes memory signature
    ) 
        external 
        onlyMasterStation 
        onlyRegisteredOutstation(outstationId) 
    {
        // Verify the command signature
        bytes32 commandHash = keccak256(abi.encodePacked(outstationId, pointIndex, value));
        address signer = recoverSigner(commandHash, signature);
        require(signer == masterStation, "Invalid signature");

        // Update binary output state
        outstations[outstationId].binaryOutputs[pointIndex] = value;
        emit ControlCommandIssued(outstationId, pointIndex, value);
        emit CommandVerified(outstationId, commandHash, true);
    }

    // Update an analog input data point
    function updateAnalogInput(
        uint256 outstationId,
        uint256 pointIndex,
        uint256 value,
        bytes memory signature
    ) 
        external 
        onlyRegisteredOutstation(outstationId) 
    {
        Outstation storage outstation = outstations[outstationId];
        require(msg.sender == outstation.deviceAddress, "Only outstation can update");

        // Verify the data signature
        bytes32 dataHash = keccak256(abi.encodePacked(outstationId, pointIndex, value));
        address signer = recoverSigner(dataHash, signature);
        require(signer == outstation.deviceAddress, "Invalid signature");

        // Update analog input
        outstation.analogInputs[pointIndex] = value;
        emit DataPointUpdated(outstationId, pointIndex, value);
        emit CommandVerified(outstationId, dataHash, true);
    }

    // Get outstation details
    function getOutstationDetails(uint256 outstationId) 
        external 
        view 
        returns (address, bytes memory, bool) 
    {
        Outstation storage outstation = outstations[outstationId];
        return (outstation.deviceAddress, outstation.publicKey, outstation.registered);
    }

    // Get analog input value
    function getAnalogInput(uint256 outstationId, uint256 pointIndex) 
        external 
        view 
        onlyRegisteredOutstation(outstationId) 
        returns (uint256) 
    {
        return outstations[outstationId].analogInputs[pointIndex];
    }

    // Get binary output state
    function getBinaryOutput(uint256 outstationId, uint256 pointIndex) 
        external 
        view 
        onlyRegisteredOutstation(outstationId) 
        returns (bool) 
    {
        return outstations[outstationId].binaryOutputs[pointIndex];
    }

    // Helper function to recover signer from a signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) 
        internal 
        pure 
        returns (address) 
    {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");
        return ecrecover(messageHash, v, r, s);
    }

    // Prevent accidental ETH deposits
    receive() external payable {
        revert("Contract does not accept ETH");
    }
}