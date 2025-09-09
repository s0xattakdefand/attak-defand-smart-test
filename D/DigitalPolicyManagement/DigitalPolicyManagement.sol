// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalPolicyManagement
 * @dev A smart contract for managing digital policies with versioning, access control, and paid enforcement rights.
 * Supports policy registration, updates, verification, and chain-of-custody tracking.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalPolicyManagement {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or modifier
        string action; // Description of the action (e.g., "Policy created", "Policy accessed")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent a policy version
    struct PolicyVersion {
        bytes32 policyHash; // Keccak-256 hash of the policy content (e.g., JSON rules)
        string description; // Description of the policy version
        uint256 versionNumber; // Version number of the policy
        uint256 timestamp; // Timestamp of version creation
    }

    // Struct to represent a digital policy
    struct Policy {
        string policyName; // Name of the policy
        string policyType; // Type of policy (e.g., "Access Control", "Privacy", "Compliance")
        address owner; // Owner of the policy
        uint256 price; // Price in wei for accessing enforcement rights
        address[] authorizedEnforcers; // List of addresses authorized to enforce the policy
        PolicyVersion[] versions; // Array of policy versions
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of policy creation
        bool exists; // Flag to check if policy exists
    }

    // Mapping to store policies by their unique ID
    mapping(bytes32 => Policy) public policies;
    // Mapping to track policies by owner
    mapping(address => bytes32[]) public ownerPolicies;

    // Event emitted when a new policy is created
    event PolicyCreated(bytes32 indexed policyId, string policyName, address indexed owner, string policyType, bytes32 initialPolicyHash);
    // Event emitted when a new policy version is added
    event PolicyVersionAdded(bytes32 indexed policyId, uint256 versionNumber, bytes32 policyHash, string description);
    // Event emitted when a policy is updated
    event PolicyUpdated(bytes32 indexed policyId, string newPolicyName, string newPolicyType, uint256 newPrice);
    // Event emitted when policy ownership is transferred
    event PolicyTransferred(bytes32 indexed policyId, address indexed newOwner);
    // Event emitted when an enforcer is authorized
    event EnforcerAuthorized(bytes32 indexed policyId, address indexed enforcer);
    // Event emitted when a policy is accessed (purchased)
    event PolicyAccessed(bytes32 indexed policyId, address indexed enforcer, uint256 price);
    // Event emitted when a policy version is verified
    event PolicyVerified(bytes32 indexed policyId, uint256 versionNumber, address indexed verifier, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed policyId, address indexed custodian, string action);

    // Modifier to check if the caller is the owner of the policy
    modifier onlyOwner(bytes32 policyId) {
        require(policies[policyId].owner == msg.sender, "Only the owner can perform this action");
        require(policies[policyId].exists, "Policy does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized enforcer or owner
    modifier onlyAuthorized(bytes32 policyId) {
        require(policies[policyId].exists, "Policy does not exist");
        bool isAuthorized = policies[policyId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < policies[policyId].authorizedEnforcers.length; i++) {
                if (policies[policyId].authorizedEnforcers[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized enforcers or owner can perform this action");
        _;
    }

    /**
     * @dev Creates a new digital policy with an initial version.
     * @param _policyHash The Keccak-256 hash of the initial policy content.
     * @param _policyName The name of the policy.
     * @param _policyType The type of policy (e.g., "Access Control", "Privacy").
     * @param _description The description of the initial policy version.
     * @param _price The price in wei for accessing enforcement rights.
     * @return policyId The unique ID of the policy.
     */
    function createPolicy(
        bytes32 _policyHash,
        string memory _policyName,
        string memory _policyType,
        string memory _description,
        uint256 _price
    ) public returns (bytes32) {
        require(_policyHash != bytes32(0), "Policy hash cannot be empty");
        require(bytes(_policyName).length > 0, "Policy name cannot be empty");
        require(bytes(_policyType).length > 0, "Policy type cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(_price >= 0, "Price cannot be negative");

        // Generate a unique policy ID
        bytes32 policyId = keccak256(abi.encodePacked(_policyHash, msg.sender, block.timestamp));
        
        // Ensure the policy doesn't already exist
        require(!policies[policyId].exists, "Policy with this ID already exists");

        // Initialize the policy
        Policy storage newPolicy = policies[policyId];
        newPolicy.policyName = _policyName;
        newPolicy.policyType = _policyType;
        newPolicy.owner = msg.sender;
        newPolicy.price = _price;
        newPolicy.timestamp = block.timestamp;
        newPolicy.exists = true;

        // Add initial version
        newPolicy.versions.push(PolicyVersion({
            policyHash: _policyHash,
            description: _description,
            versionNumber: 1,
            timestamp: block.timestamp
        }));

        // Initialize the custody log with the creation entry
        newPolicy.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Policy created",
            timestamp: block.timestamp
        }));

        // Add policy ID to owner's list
        ownerPolicies[msg.sender].push(policyId);

        // Emit events for policy creation and custody update
        emit PolicyCreated(policyId, _policyName, msg.sender, _policyType, _policyHash);
        emit PolicyVersionAdded(policyId, 1, _policyHash, _description);
        emit CustodyUpdated(policyId, msg.sender, "Policy created");

        return policyId;
    }

    /**
     * @dev Adds a new version to an existing policy.
     * @param _policyId The ID of the policy.
     * @param _policyHash The Keccak-256 hash of the new policy content.
     * @param _description The description of the new policy version.
     */
    function addPolicyVersion(
        bytes32 _policyId,
        bytes32 _policyHash,
        string memory _description
    ) public onlyOwner(_policyId) {
        require(_policyHash != bytes32(0), "Policy hash cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        Policy storage policy = policies[_policyId];
        uint256 newVersionNumber = policy.versions.length + 1;

        // Add new version
        policy.versions.push(PolicyVersion({
            policyHash: _policyHash,
            description: _description,
            versionNumber: newVersionNumber,
            timestamp: block.timestamp
        }));

        // Add custody log entry for version addition
        policy.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "New policy version added",
            timestamp: block.timestamp
        }));

        // Emit events for version addition and custody update
        emit PolicyVersionAdded(_policyId, newVersionNumber, _policyHash, _description);
        emit CustodyUpdated(_policyId, msg.sender, "New policy version added");
    }

    /**
     * @dev Updates the name, type, or price of an existing policy.
     * @param _policyId The ID of the policy.
     * @param _newPolicyName The new name for the policy.
     * @param _newPolicyType The new policy type.
     * @param _newPrice The new price in wei for enforcement rights.
     */
    function updatePolicy(
        bytes32 _policyId,
        string memory _newPolicyName,
        string memory _newPolicyType,
        uint256 _newPrice
    ) public onlyOwner(_policyId) {
        require(bytes(_newPolicyName).length > 0, "Policy name cannot be empty");
        require(bytes(_newPolicyType).length > 0, "Policy type cannot be empty");
        require(_newPrice >= 0, "Price cannot be negative");

        Policy storage policy = policies[_policyId];
        policy.policyName = _newPolicyName;
        policy.policyType = _newPolicyType;
        policy.price = _newPrice;

        // Add custody log entry for update
        policy.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Policy updated",
            timestamp: block.timestamp
        }));

        // Emit events for policy update and custody update
        emit PolicyUpdated(_policyId, _newPolicyName, _newPolicyType, _newPrice);
        emit CustodyUpdated(_policyId, msg.sender, "Policy updated");
    }

    /**
     * @dev Transfers ownership of a policy to a new address.
     * @param _policyId The ID of the policy.
     * @param _newOwner The address of the new owner.
     */
    function transferPolicyOwnership(bytes32 _policyId, address _newOwner) public onlyOwner(_policyId) {
        require(_newOwner != address(0), "New owner address cannot be zero");
        require(_newOwner != policies[_policyId].owner, "New owner must be different");

        // Update ownership
        policies[_policyId].owner = _newOwner;

        // Add custody log entry for transfer
        policies[_policyId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Ownership transferred to new owner",
            timestamp: block.timestamp
        }));

        // Update ownerPolicies mappings
        bytes32[] storage ownerRecords = ownerPolicies[msg.sender];
        for (uint256 i = 0; i < ownerRecords.length; i++) {
            if (ownerRecords[i] == _policyId) {
                ownerRecords[i] = ownerRecords[ownerRecords.length - 1];
                ownerRecords.pop();
                break;
            }
        }
        ownerPolicies[_newOwner].push(_policyId);

        // Emit events for ownership transfer and custody update
        emit PolicyTransferred(_policyId, _newOwner);
        emit CustodyUpdated(_policyId, msg.sender, "Ownership transferred to new owner");
    }

    /**
     * @dev Authorizes an enforcer to access and enforce a policy.
     * @param _policyId The ID of the policy.
     * @param _enforcer The address of the enforcer to authorize.
     */
    function authorizeEnforcer(bytes32 _policyId, address _enforcer) public onlyOwner(_policyId) {
        require(_enforcer != address(0), "Enforcer address cannot be zero");
        // Check if enforcer is already authorized
        for (uint256 i = 0; i < policies[_policyId].authorizedEnforcers.length; i++) {
            require(policies[_policyId].authorizedEnforcers[i] != _enforcer, "Enforcer already authorized");
        }
        policies[_policyId].authorizedEnforcers.push(_enforcer);

        // Add custody log entry for authorization
        policies[_policyId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Enforcer authorized",
            timestamp: block.timestamp
        }));

        // Emit events for enforcer authorization and custody update
        emit EnforcerAuthorized(_policyId, _enforcer);
        emit CustodyUpdated(_policyId, msg.sender, "Enforcer authorized");
    }

    /**
     * @dev Allows an enforcer to access (purchase) enforcement rights for a policy.
     * @param _policyId The ID of the policy.
     */
    function accessPolicy(bytes32 _policyId) public payable {
        require(policies[_policyId].exists, "Policy does not exist");
        require(msg.value >= policies[_policyId].price, "Insufficient payment");
        require(msg.sender != policies[_policyId].owner, "Owner cannot purchase own policy");

        // Check if enforcer is already authorized
        bool isAuthorized = false;
        for (uint256 i = 0; i < policies[_policyId].authorizedEnforcers.length; i++) {
            if (policies[_policyId].authorizedEnforcers[i] == msg.sender) {
                isAuthorized = true;
                break;
            }
        }
        if (!isAuthorized) {
            policies[_policyId].authorizedEnforcers.push(msg.sender);
        }

        // Transfer payment to the owner
        address owner = policies[_policyId].owner;
        uint256 price = policies[_policyId].price;
        (bool success, ) = owner.call{value: price}("");
        require(success, "Payment transfer failed");

        // Refund excess payment if any
        if (msg.value > price) {
            (bool refundSuccess, ) = msg.sender.call{value: msg.value - price}("");
            require(refundSuccess, "Refund transfer failed");
        }

        // Add custody log entry for access
        policies[_policyId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Policy accessed",
            timestamp: block.timestamp
        }));

        // Emit events for policy access and custody update
        emit PolicyAccessed(_policyId, msg.sender, price);
        emit CustodyUpdated(_policyId, msg.sender, "Policy accessed");
    }

    /**
     * @dev Verifies a policy version against provided policy content hash.
     * @param _policyId The ID of the policy.
     * @param _versionNumber The version number to verify.
     * @param _policyHash The hash of the policy content to verify.
     * @return isValid True if the policy hash matches the stored hash for the version, false otherwise.
     */
    function verifyPolicy(bytes32 _policyId, uint256 _versionNumber, bytes32 _policyHash) public onlyAuthorized(_policyId) returns (bool) {
        require(policies[_policyId].exists, "Policy does not exist");
        require(_versionNumber > 0 && _versionNumber <= policies[_policyId].versions.length, "Invalid version number");
        require(_policyHash != bytes32(0), "Policy hash cannot be empty");

        PolicyVersion storage version = policies[_policyId].versions[_versionNumber - 1];
        bool isValid = (_policyHash == version.policyHash);

        // Emit event for policy verification
        emit PolicyVerified(_policyId, _versionNumber, msg.sender, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a policy.
     * @param _policyId The ID of the policy.
     * @return policyName The name of the policy.
     * @return policyType The type of policy.
     * @return owner The owner of the policy.
     * @return price The price for enforcement rights.
     * @return timestamp The timestamp of policy creation.
     */
    function getPolicy(bytes32 _policyId)
        public
        view
        onlyAuthorized(_policyId)
        returns (
            string memory policyName,
            string memory policyType,
            address owner,
            uint256 price,
            uint256 timestamp
        )
    {
        require(policies[_policyId].exists, "Policy does not exist");
        Policy storage policy = policies[_policyId];
        return (
            policy.policyName,
            policy.policyType,
            policy.owner,
            policy.price,
            policy.timestamp
        );
    }

    /**
     * @dev Retrieves the details of a specific policy version.
     * @param _policyId The ID of the policy.
     * @param _versionNumber The version number to retrieve.
     * @return policyHash The hash of the policy content.
     * @return description The description of the version.
     * @return versionNumber The version number.
     * @return timestamp The timestamp of version creation.
     */
    function getPolicyVersion(bytes32 _policyId, uint256 _versionNumber)
        public
        view
        onlyAuthorized(_policyId)
        returns (
            bytes32 policyHash,
            string memory description,
            uint256 versionNumber,
            uint256 timestamp
        )
    {
        require(policies[_policyId].exists, "Policy does not exist");
        require(_versionNumber > 0 && _versionNumber <= policies[_policyId].versions.length, "Invalid version number");
        PolicyVersion storage version = policies[_policyId].versions[_versionNumber - 1];
        return (
            version.policyHash,
            version.description,
            version.versionNumber,
            version.timestamp
        );
    }

    /**
     * @dev Retrieves the list of authorized enforcers for a policy.
     * @param _policyId The ID of the policy.
     * @return The array of authorized enforcer addresses.
     */
    function getAuthorizedEnforcers(bytes32 _policyId)
        public
        view
        onlyOwner(_policyId)
        returns (address[] memory)
    {
        return policies[_policyId].authorizedEnforcers;
    }

    /**
     * @dev Retrieves the chain-of-custody log for a policy.
     * @param _policyId The ID of the policy.
     * @return custodians The array of custodian addresses.
     * @return actions The array of action descriptions.
     * @return timestamps The array of action timestamps.
     */
    function getCustodyLog(bytes32 _policyId)
        public
        view
        onlyAuthorized(_policyId)
        returns (
            address[] memory custodians,
            string[] memory actions,
            uint256[] memory timestamps
        )
    {
        require(policies[_policyId].exists, "Policy does not exist");
        Policy storage policy = policies[_policyId];
        uint256 logLength = policy.custodyLog.length;

        custodians = new address[](logLength);
        actions = new string[](logLength);
        timestamps = new uint256[](logLength);

        for (uint256 i = 0; i < logLength; i++) {
            custodians[i] = policy.custodyLog[i].custodian;
            actions[i] = policy.custodyLog[i].action;
            timestamps[i] = policy.custodyLog[i].timestamp;
        }

        return (custodians, actions, timestamps);
    }

    /**
     * @dev Retrieves the list of policy IDs for a given owner.
     * @param _owner The address of the owner.
     * @return The array of policy IDs.
     */
    function getOwnerPolicies(address _owner) public view returns (bytes32[] memory) {
        return ownerPolicies[_owner];
    }
}