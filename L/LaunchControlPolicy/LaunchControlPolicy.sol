// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title LaunchControlPolicyAttackDefense - Full Attack and Defense Simulation for Launch Control Policies in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Launch Control (Immediate Launch, No Checks)
contract InsecureLaunchControl {
    bool public launched;
    string public launchConfig;

    event Launched(string config);

    function setLaunchConfig(string calldata config) external {
        launchConfig = config;
    }

    function launch() external {
        require(!launched, "Already launched");
        launched = true;
        emit Launched(launchConfig);
    }
}

/// @notice Secure Launch Control (Multi-Sig + Parameter Lock + Timelock)
contract SecureLaunchControl {
    address public immutable owner;
    mapping(address => bool) public authorizedSigners;
    uint256 public constant REQUIRED_APPROVALS = 2;
    uint256 public constant TIMELOCK_DURATION = 2 minutes;

    string public launchConfig;
    bool public configLocked;
    bool public launched;
    uint256 public launchReadyTime;

    mapping(bytes32 => uint256) public approvals;

    event ConfigProposed(string config);
    event ConfigLocked(string config);
    event LaunchApproved(bytes32 indexed proposalHash, address indexed signer);
    event LaunchExecuted(string config);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyAuthorized() {
        require(authorizedSigners[msg.sender], "Not authorized signer");
        _;
    }

    constructor(address[] memory _authorizedSigners) {
        owner = msg.sender;
        for (uint256 i = 0; i < _authorizedSigners.length; i++) {
            authorizedSigners[_authorizedSigners[i]] = true;
        }
    }

    function proposeConfig(string calldata config) external onlyOwner {
        require(!configLocked, "Config already locked");
        launchConfig = config;
        emit ConfigProposed(config);
    }

    function lockConfig() external onlyOwner {
        require(bytes(launchConfig).length > 0, "No config proposed");
        configLocked = true;
        launchReadyTime = block.timestamp + TIMELOCK_DURATION;
        emit ConfigLocked(launchConfig);
    }

    function approveLaunch() external onlyAuthorized {
        require(configLocked, "Config not locked");
        bytes32 proposalHash = keccak256(abi.encodePacked(launchConfig));
        require(approvals[proposalHash] < REQUIRED_APPROVALS, "Already enough approvals");

        approvals[proposalHash] += 1;
        emit LaunchApproved(proposalHash, msg.sender);
    }

    function executeLaunch() external {
        require(configLocked, "Config not locked");
        require(block.timestamp >= launchReadyTime, "Timelock not expired");

        bytes32 proposalHash = keccak256(abi.encodePacked(launchConfig));
        require(approvals[proposalHash] >= REQUIRED_APPROVALS, "Not enough approvals");

        launched = true;
        emit LaunchExecuted(launchConfig);
    }
}

/// @notice Attack contract simulating unauthorized or rushed launch
contract LaunchControlIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function rushLaunch() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("launch()")
        );
    }
}
