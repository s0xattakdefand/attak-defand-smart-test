// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DigitalPolicy
 * @dev A smart contract for managing digital policies with metadata, access control, and verification.
 * Supports policy registration, updates, and chain-of-custody tracking.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DigitalPolicy {
    // Struct to represent a chain-of-custody entry
    struct CustodyEntry {
        address custodian; // Address of the custodian or modifier
        string action; // Description of the action (e.g., "Policy created", "Policy updated")
        uint256 timestamp; // Timestamp of the action
    }

    // Struct to represent a digital policy
    struct Policy {
        bytes32 policyHash; // Keccak-256 hash of the policy content (e.g., JSON rules)
        string description; // Description of the policy
        string policyType; // Type of policy (e.g., "Access Control", "Privacy", "Compliance")
        address owner; // Owner of the policy
        address[] authorizedVerifiers; // List of addresses authorized to verify the policy
        CustodyEntry[] custodyLog; // Chain-of-custody log
        uint256 timestamp; // Timestamp of policy creation
        bool exists; // Flag to check if policy exists
    }

    // Mapping to store policies by their unique ID
    mapping(bytes32 => Policy) public policies;
    // Mapping to track policies by owner
    mapping(address => bytes32[]) public ownerPolicies;

    // Event emitted when a new policy is created
    event PolicyCreated(bytes32 indexed policyId, bytes32 policyHash, address indexed owner, string description, string policyType);
    // Event emitted when a policy is updated
    event PolicyUpdated(bytes32 indexed policyId, string newDescription, string newPolicyType);
    // Event emitted when policy ownership is transferred
    event PolicyTransferred(bytes32 indexed policyId, address indexed newOwner);
    // Event emitted when a verifier is authorized
    event VerifierAuthorized(bytes32 indexed policyId, address indexed verifier);
    // Event emitted when a policy is verified
    event PolicyVerified(bytes32 indexed policyId, address indexed verifier, bool isValid);
    // Event emitted when a custody entry is added
    event CustodyUpdated(bytes32 indexed policyId, address indexed custodian, string action);

    // Modifier to check if the caller is the owner of the policy
    modifier onlyOwner(bytes32 policyId) {
        require(policies[policyId].owner == msg.sender, "Only the owner can perform this action");
        require(policies[policyId].exists, "Policy does not exist");
        _;
    }

    // Modifier to check if the caller is an authorized verifier or owner
    modifier onlyAuthorized(bytes32 policyId) {
        require(policies[policyId].exists, "Policy does not exist");
        bool isAuthorized = policies[policyId].owner == msg.sender;
        if (!isAuthorized) {
            for (uint256 i = 0; i < policies[policyId].authorizedVerifiers.length; i++) {
                if (policies[policyId].authorizedVerifiers[i] == msg.sender) {
                    isAuthorized = true;
                    break;
                }
            }
        }
        require(isAuthorized, "Only authorized verifiers or owner can perform this action");
        _;
    }

    /**
     * @dev Creates a new digital policy.
     * @param _policyHash The Keccak-256 hash of the policy content (e.g., JSON rules).
     * @param _description The description of the policy.
     * @param _policyType The type of policy (e.g., "Access Control", "Privacy").
     * @return policyId The unique ID of the policy.
     */
    function createPolicy(
        bytes32 _policyHash,
        string memory _description,
        string memory _policyType
    ) public returns (bytes32) {
        require(_policyHash != bytes32(0), "Policy hash cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(bytes(_policyType).length > 0, "Policy type cannot be empty");

        // Generate a unique policy ID
        bytes32 policyId = keccak256(abi.encodePacked(_policyHash, msg.sender, block.timestamp));
        
        // Ensure the policy doesn't already exist
        require(!policies[policyId].exists, "Policy with this ID already exists");

        // Initialize the policy
        Policy storage newPolicy = policies[policyId];
        newPolicy.policyHash = _policyHash;
        newPolicy.description = _description;
        newPolicy.policyType = _policyType;
        newPolicy.owner = msg.sender;
        newPolicy.timestamp = block.timestamp;
        newPolicy.exists = true;

        // Initialize the custody log with the creation entry
        newPolicy.custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Policy created",
            timestamp: block.timestamp
        }));

        // Add policy ID to owner's list
        ownerPolicies[msg.sender].push(policyId);

        // Emit events for policy creation and custody update
        emit PolicyCreated(policyId, _policyHash, msg.sender, _description, _policyType);
        emit CustodyUpdated(policyId, msg.sender, "Policy created");

        return policyId;
    }

    /**
     * @dev Updates the description or type of an existing policy.
     * @param _policyId The ID of the policy.
     * @param _newDescription The new description for the policy.
     * @param _newPolicyType The new policy type.
     */
    function updatePolicy(
        bytes32 _policyId,
        string memory _newDescription,
        string memory _newPolicyType
    ) public onlyOwner(_policyId) {
        require(bytes(_newDescription).length > 0, "Description cannot be empty");
        require(bytes(_newPolicyType).length > 0, "Policy type cannot be empty");

        policies[_policyId].description = _newDescription;
        policies[_policyId].policyType = _newPolicyType;

        // Add custody log entry for update
        policies[_policyId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Policy updated",
            timestamp: block.timestamp
        }));

        // Emit events for policy update and custody update
        emit PolicyUpdated(_policyId, _newDescription, _newPolicyType);
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
     * @dev Authorizes a verifier to access a policy.
     * @param _policyId The ID of the policy.
     * @param _verifier The address of the verifier to authorize.
     */
    function authorizeVerifier(bytes32 _policyId, address _verifier) public onlyOwner(_policyId) {
        require(_verifier != address(0), "Verifier address cannot be zero");
        // Check if verifier is already authorized
        for (uint256 i = 0; i < policies[_policyId].authorizedVerifiers.length; i++) {
            require(policies[_policyId].authorizedVerifiers[i] != _verifier, "Verifier already authorized");
        }
        policies[_policyId].authorizedVerifiers.push(_verifier);

        // Add custody log entry for authorization
        policies[_policyId].custodyLog.push(CustodyEntry({
            custodian: msg.sender,
            action: "Verifier authorized",
            timestamp: block.timestamp
        }));

        // Emit events for verifier authorization and custody update
        emit VerifierAuthorized(_policyId, _verifier);
        emit CustodyUpdated(_policyId, msg.sender, "Verifier authorized");
    }

    /**
     * @dev Verifies a policy against provided policy content hash.
     * @param _policyId The ID of the policy.
     * @param _policyHash The hash of the policy content to verify.
     * @return isValid True if the policy hash matches the stored hash, false otherwise.
     */
    function verifyPolicy(bytes32 _policyId, bytes32 _policyHash) public onlyAuthorized(_policyId) returns (bool) {
        require(policies[_policyId].exists, "Policy does not exist");
        require(_policyHash != bytes32(0), "Policy hash cannot be empty");

        bool isValid = (_policyHash == policies[_policyId].policyHash);

        // Emit event for policy verification
        emit PolicyVerified(_policyId, msg.sender, isValid);

        return isValid;
    }

    /**
     * @dev Retrieves the details of a policy.
     * @param _policyId The ID of the policy.
     * @return policyHash The stored policy hash.
     * @return description The description of the policy.
     * @return policyType The type of policy.
     * @return owner The owner of the policy.
     * @return timestamp The timestamp of policy creation.
     */
    function getPolicy(bytes32 _policyId)
        public
        view
        onlyAuthorized(_policyId)
        returns (
            bytes32 policyHash,
            string memory description,
            string memory policyType,
            address owner,
            uint256 timestamp
        )
    {
        require(policies[_policyId].exists, "Policy does not exist");
        Policy storage policy = policies[_policyId];
        return (
            policy.policyHash,
            policy.description,
            policy.policyType,
            policy.owner,
            policy.timestamp
        );
    }

    /**
     * @dev Retrieves the list of authorized verifiers for a policy.
     * @param _policyId The ID of the policy.
     * @return The array of authorized verifier addresses.
     */
    function getAuthorizedVerifiers(bytes32 _policyId)
        public
        view
        onlyOwner(_policyId)
        returns (address[] memory)
    {
        return policies[_policyId].authorizedVerifiers;
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