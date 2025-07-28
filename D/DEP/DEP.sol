// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// DEP contract for managing Distributed Energy Prosumer demand response
contract DEP {
    // Contract owner (e.g., grid operator or utility provider)
    address public owner;

    // Structure to store prosumer energy profile
    struct EnergyProfile {
        uint256 baselineEnergy; // Baseline energy consumption (in watt-hours)
        uint256 currentEnergy; // Current monitored energy consumption (in watt-hours)
        uint256 expectedEnergy; // Expected energy after DR adjustment (in watt-hours)
        uint256 flexibilityAmount; // Energy flexibility to shift during DR (in watt-hours)
        uint256 lastUpdateTimestamp; // Timestamp of last profile update
        bool enrolled; // Whether prosumer is enrolled in DR program
    }

    // Structure to store DR event details
    struct DemandResponseEvent {
        bytes32 eventId; // Unique event identifier
        uint256 startTime; // Event start timestamp
        uint256 endTime; // Event end timestamp
        uint256 targetReduction; // Target energy reduction (in watt-hours)
        uint256 rewardAmount; // Reward for compliance (in wei)
        bool active; // Whether event is active
    }

    // Structure to store prosumer submission metadata for rate limiting
    struct SubmissionInfo {
        uint256 lastSubmissionTimestamp; // Timestamp of last submission
        uint256 submissionCount; // Number of submissions in current window
    }

    // Mapping to store prosumer energy profiles
    mapping(address => EnergyProfile) public energyProfiles;

    // Mapping to store DR events by event ID
    mapping(bytes32 => DemandResponseEvent) public drEvents;

    // Mapping to store authorized IoT metering devices
    mapping(address => bool) public authorizedDevices;

    // Mapping to store submission metadata for rate limiting
    mapping(address => SubmissionInfo) public submissionInfo;

    // Rate limit parameters to prevent DoS
    uint256 public constant SUBMISSION_WINDOW = 1 hours; // Time window for rate limiting
    uint256 public constant MAX_SUBMISSIONS_PER_WINDOW = 5; // Max submissions per window
    uint256 public constant MIN_SUBMISSION_INTERVAL = 10 seconds; // Minimum time between submissions

    // Event emitted when a prosumer enrolls in the DR program
    event ProsumerEnrolled(address indexed prosumer, uint256 baselineEnergy, uint256 timestamp);

    // Event emitted when a prosumer updates their energy profile
    event EnergyProfileUpdated(address indexed prosumer, uint256 currentEnergy, uint256 expectedEnergy, uint256 flexibilityAmount, uint256 timestamp);

    // Event emitted when a DR event is created
    event DREventCreated(bytes32 indexed eventId, uint256 startTime, uint256 endTime, uint256 targetReduction, uint256 rewardAmount, uint256 timestamp);

    // Event emitted when a prosumer complies with a DR event
    event DREventCompliance(address indexed prosumer, bytes32 indexed eventId, uint256 reductionAchieved, uint256 reward, uint256 timestamp);

    // Event emitted when a device is authorized or deauthorized
    event DeviceAuthorizationUpdated(address indexed device, bool authorized, uint256 timestamp);

    // Event emitted when rate limit is triggered
    event RateLimitTriggered(address indexed device, uint256 timestamp);

    // Modifier to restrict functions to the contract owner
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    // Modifier to restrict functions to authorized IoT devices
    modifier onlyAuthorizedDevice() {
        require(authorizedDevices[msg.sender], "Only authorized devices can call this function");
        _;
    }

    // Modifier to check if a prosumer is enrolled
    modifier onlyEnrolled(address prosumer) {
        require(energyProfiles[prosumer].enrolled, "Prosumer not enrolled");
        _;
    }

    // Modifier to check if a DR event exists and is active
    modifier eventActive(bytes32 eventId) {
        require(drEvents[eventId].active, "DR event not active or does not exist");
        require(block.timestamp >= drEvents[eventId].startTime && block.timestamp <= drEvents[eventId].endTime, "DR event not within active time");
        _;
    }

    // Constructor to set the owner
    constructor() {
        owner = msg.sender;
        authorizedDevices[msg.sender] = true; // Owner is an authorized device by default
    }

    // Function to enroll a prosumer in the DR program
    function enrollProsumer(address prosumer, uint256 baselineEnergy) external onlyOwner {
        require(prosumer != address(0), "Prosumer cannot be zero address");
        require(!energyProfiles[prosumer].enrolled, "Prosumer already enrolled");
        require(baselineEnergy > 0, "Baseline energy must be greater than zero");

        energyProfiles[prosumer] = EnergyProfile({
            baselineEnergy: baselineEnergy,
            currentEnergy: baselineEnergy,
            expectedEnergy: baselineEnergy,
            flexibilityAmount: 0,
            lastUpdateTimestamp: block.timestamp,
            enrolled: true
        });

        emit ProsumerEnrolled(prosumer, baselineEnergy, block.timestamp);
    }

    // Function to update energy profile by an authorized IoT device
    function updateEnergyProfile(address prosumer, uint256 currentEnergy, uint256 expectedEnergy, uint256 flexibilityAmount)
        external
        onlyAuthorizedDevice
        onlyEnrolled(prosumer)
    {
        // Rate limiting
        SubmissionInfo storage deviceInfo = submissionInfo[msg.sender];
        if (block.timestamp >= deviceInfo.lastSubmissionTimestamp + SUBMISSION_WINDOW) {
            deviceInfo.submissionCount = 0;
            deviceInfo.lastSubmissionTimestamp = block.timestamp;
        } else {
            require(
                block.timestamp >= deviceInfo.lastSubmissionTimestamp + MIN_SUBMISSION_INTERVAL,
                "Submission interval too short"
            );
            require(deviceInfo.submissionCount < MAX_SUBMISSIONS_PER_WINDOW, "Submission limit exceeded");
            emit RateLimitTriggered(msg.sender, block.timestamp);
        }

        deviceInfo.submissionCount += 1;

        EnergyProfile storage profile = energyProfiles[prosumer];
        profile.currentEnergy = currentEnergy;
        profile.expectedEnergy = expectedEnergy;
        profile.flexibilityAmount = flexibilityAmount;
        profile.lastUpdateTimestamp = block.timestamp;

        emit EnergyProfileUpdated(prosumer, currentEnergy, expectedEnergy, flexibilityAmount, block.timestamp);
    }

    // Function to create a DR event
    function createDREvent(
        bytes32 eventId,
        uint256 startTime,
        uint256 endTime,
        uint256 targetReduction,
        uint256 rewardAmount
    ) external onlyOwner {
        require(!drEvents[eventId].active, "DR event ID already exists");
        require(startTime > block.timestamp, "Start time must be in the future");
        require(endTime > startTime, "End time must be after start time");
        require(targetReduction > 0, "Target reduction must be greater than zero");
        require(rewardAmount > 0, "Reward amount must be greater than zero");

        drEvents[eventId] = DemandResponseEvent({
            eventId: eventId,
            startTime: startTime,
            endTime: endTime,
            targetReduction: targetReduction,
            rewardAmount: rewardAmount,
            active: true
        });

        emit DREventCreated(eventId, startTime, endTime, targetReduction, rewardAmount, block.timestamp);
    }

    // Function to check compliance and issue rewards for a DR event
    function checkCompliance(address prosumer, bytes32 eventId)
        external
        onlyAuthorizedDevice
        onlyEnrolled(prosumer)
        eventActive(eventId)
    {
        EnergyProfile memory profile = energyProfiles[prosumer];
        DemandResponseEvent memory drEvent = drEvents[eventId];

        // Calculate reduction achieved
        uint256 reductionAchieved = profile.baselineEnergy > profile.currentEnergy
            ? profile.baselineEnergy - profile.currentEnergy
            : 0;

        // Check if target reduction is met
        if (reductionAchieved >= drEvent.targetReduction) {
            // Issue reward (in wei, for simplicity; assumes contract is funded)
            (bool success, ) = prosumer.call{value: drEvent.rewardAmount}("");
            require(success, "Reward transfer failed");

            emit DREventCompliance(prosumer, eventId, reductionAchieved, drEvent.rewardAmount, block.timestamp);
        } else {
            // Optionally implement penalties or restrictions here
            emit DREventCompliance(prosumer, eventId, reductionAchieved, 0, block.timestamp);
        }
    }

    // Function to authorize or deauthorize an IoT device
    function setDeviceAuthorization(address device, bool authorized) external onlyOwner {
        require(device != address(0), "Device cannot be zero address");
        require(authorizedDevices[device] != authorized, "Authorization status already set");

        authorizedDevices[device] = authorized;
        emit DeviceAuthorizationUpdated(device, authorized, block.timestamp);
    }

    // Function to get prosumer energy profile
    function getEnergyProfile(address prosumer)
        external
        view
        onlyEnrolled(prosumer)
        returns (
            uint256 baselineEnergy,
            uint256 currentEnergy,
            uint256 expectedEnergy,
            uint256 flexibilityAmount,
            uint256 lastUpdateTimestamp
        )
    {
        require(
            msg.sender == owner ||
            msg.sender == prosumer ||
            authorizedDevices[msg.sender],
            "Not authorized to view profile"
        );

        EnergyProfile memory profile = energyProfiles[prosumer];
        return (
            profile.baselineEnergy,
            profile.currentEnergy,
            profile.expectedEnergy,
            profile.flexibilityAmount,
            profile.lastUpdateTimestamp
        );
    }

    // Function to get DR event details
    function getDREventDetails(bytes32 eventId)
        external
        view
        returns (
            uint256 startTime,
            uint256 endTime,
            uint256 targetReduction,
            uint256 rewardAmount,
            bool active
        )
    {
        require(drEvents[eventId].active, "DR event does not exist");
        DemandResponseEvent memory drEvent = drEvents[eventId];
        return (
            drEvent.startTime,
            drEvent.endTime,
            drEvent.targetReduction,
            drEvent.rewardAmount,
            drEvent.active
        );
    }

    // Function to transfer ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "New owner cannot be zero address");
        authorizedDevices[owner] = false; // Remove old owner as authorized device
        owner = newOwner;
        authorizedDevices[newOwner] = true; // New owner becomes an authorized device
        emit DeviceAuthorizationUpdated(newOwner, true, block.timestamp);
    }

    // Fallback function to receive Ether (e.g., for funding rewards)
    receive() external payable {
        emit FundsDeposited(msg.sender, msg.value, block.timestamp);
    }

    // Event emitted when funds are deposited
    event FundsDeposited(address indexed sender, uint256 amount, uint256 timestamp);
}