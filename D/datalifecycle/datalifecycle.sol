// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DataProcessingPipeline
 * @notice
 *   Implements a generic “data processing pipeline” per NIST SP 800-188 & SP 1500-1:
 *   • RAW_DATA_ROLE may register raw inputs (off-chain pointers).
 *   • PROCESSOR_ROLE may define and execute processing stages, each transforming
 *     one or more input artifacts into outputs.
 *   • ADMIN_ROLE manages roles and pipeline configurations and may pause the contract.
 *
 * Concepts:
 *   – RawData: unprocessed inputs (e.g. sensor dumps, logs) identified by ID and URI.
 *   – Stage: named transformation step, with configurable parameters (stored off-chain).
 *   – ProcessRun: execution of a Stage on specific inputs, producing outputs (URIs).
 *
 * You can build arbitrary multi-stage workflows by chaining ProcessRuns.
 */
contract DataProcessingPipeline is AccessControl, Pausable {
    bytes32 public constant ADMIN_ROLE      = keccak256("ADMIN_ROLE");
    bytes32 public constant RAW_DATA_ROLE   = keccak256("RAW_DATA_ROLE");
    bytes32 public constant PROCESSOR_ROLE  = keccak256("PROCESSOR_ROLE");

    struct RawData {
        string uri;      // off-chain pointer (IPFS, URL, etc.)
        address owner;   // registrant
        bool exists;
    }

    struct Stage {
        string name;         // e.g. "Normalize", "Aggregate", "TrainModel"
        string configURI;    // off-chain pointer to parameters/schema
        bool exists;
    }

    struct ProcessRun {
        uint256 stageId;         // which stage was run
        uint256[] inputIds;      // rawData or previous run IDs
        string outputURI;        // off-chain pointer to result
        address executedBy;      // processor
        uint256 timestamp;
    }

    uint256 private _nextRawId     = 1;
    uint256 private _nextStageId   = 1;
    uint256 private _nextRunId     = 1;

    mapping(uint256 => RawData)     private _rawData;
    mapping(uint256 => Stage)       private _stages;
    mapping(uint256 => ProcessRun)  private _runs;

    event RawDataRegistered(uint256 indexed rawId, address indexed owner, string uri);
    event StageDefined      (uint256 indexed stageId, string name, string configURI);
    event ProcessExecuted   (
        uint256 indexed runId,
        uint256 indexed stageId,
        uint256[] inputIds,
        address indexed executedBy,
        string outputURI,
        uint256 timestamp
    );

    modifier onlyAdmin() {
        require(hasRole(ADMIN_ROLE, msg.sender), "DPP: not admin");
        _;
    }
    modifier onlyRawRegistrar() {
        require(hasRole(RAW_DATA_ROLE, msg.sender), "DPP: not raw-data role");
        _;
    }
    modifier onlyProcessor() {
        require(hasRole(PROCESSOR_ROLE, msg.sender), "DPP: not processor");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(ADMIN_ROLE, admin);
    }

    /// @notice Grant RAW_DATA_ROLE to an account
    function addRawRegistrar(address acct) external onlyAdmin {
        grantRole(RAW_DATA_ROLE, acct);
    }

    /// @notice Grant PROCESSOR_ROLE to an account
    function addProcessor(address acct) external onlyAdmin {
        grantRole(PROCESSOR_ROLE, acct);
    }

    /// @notice Pause pipeline operations
    function pause() external onlyAdmin {
        _pause();
    }

    /// @notice Unpause pipeline operations
    function unpause() external onlyAdmin {
        _unpause();
    }

    /// @notice Register a new raw data artifact
    function registerRawData(string calldata uri)
        external
        whenNotPaused
        onlyRawRegistrar
        returns (uint256 rawId)
    {
        require(bytes(uri).length > 0, "DPP: uri required");
        rawId = _nextRawId++;
        _rawData[rawId] = RawData({ uri: uri, owner: msg.sender, exists: true });
        emit RawDataRegistered(rawId, msg.sender, uri);
    }

    /// @notice Define a new processing stage
    function defineStage(string calldata name, string calldata configURI)
        external
        whenNotPaused
        onlyAdmin
        returns (uint256 stageId)
    {
        require(bytes(name).length > 0, "DPP: name required");
        stageId = _nextStageId++;
        _stages[stageId] = Stage({ name: name, configURI: configURI, exists: true });
        emit StageDefined(stageId, name, configURI);
    }

    /// @notice Execute a processing stage on given inputs
    function executeStage(
        uint256 stageId,
        uint256[] calldata inputIds,
        string calldata outputURI
    )
        external
        whenNotPaused
        onlyProcessor
        returns (uint256 runId)
    {
        Stage storage st = _stages[stageId];
        require(st.exists, "DPP: invalid stage");
        require(bytes(outputURI).length > 0, "DPP: output URI required");
        // Validate inputs exist (either raw data or previous runs)
        for (uint i = 0; i < inputIds.length; i++) {
            require(
                _rawData[inputIds[i]].exists || _runs[inputIds[i]].timestamp != 0,
                "DPP: invalid input ID"
            );
        }
        runId = _nextRunId++;
        _runs[runId] = ProcessRun({
            stageId:     stageId,
            inputIds:    inputIds,
            outputURI:   outputURI,
            executedBy:  msg.sender,
            timestamp:   block.timestamp
        });
        emit ProcessExecuted(runId, stageId, inputIds, msg.sender, outputURI, block.timestamp);
    }

    /// @notice Fetch raw data metadata
    function getRawData(uint256 rawId)
        external
        view
        returns (string memory uri, address owner)
    {
        RawData storage rd = _rawData[rawId];
        require(rd.exists, "DPP: raw not found");
        return (rd.uri, rd.owner);
    }

    /// @notice Fetch stage metadata
    function getStage(uint256 stageId)
        external
        view
        returns (string memory name, string memory configURI)
    {
        Stage storage st = _stages[stageId];
        require(st.exists, "DPP: stage not found");
        return (st.name, st.configURI);
    }

    /// @notice Fetch process run details
    function getRun(uint256 runId)
        external
        view
        returns (
            uint256 stageId,
            uint256[] memory inputIds,
            string memory outputURI,
            address executedBy,
            uint256 timestamp
        )
    {
        ProcessRun storage pr = _runs[runId];
        require(pr.timestamp != 0, "DPP: run not found");
        return (pr.stageId, pr.inputIds, pr.outputURI, pr.executedBy, pr.timestamp);
    }
}
