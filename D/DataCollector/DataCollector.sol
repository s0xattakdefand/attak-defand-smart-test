// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title ExerciseActionLogger
 * @notice
 *   Implements the “Recorder” concept from NIST SP 800-84:
 *   A person who records information about actions that occur during an exercise or test.
 *
 * Roles:
 *   • DEFAULT_ADMIN_ROLE: can pause/unpause, add/remove recorders, and create sessions.
 *   • RECORDER_ROLE: may record actions in sessions.
 *
 * Data Structures:
 *   • Session: unique sessionId, name, creation timestamp.
 *   • Action: within a session, actor (recorder), timestamp, description.
 */
contract ExerciseActionLogger is AccessControl, Pausable {
    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");

    struct Session {
        string   name;
        uint256  createdAt;
        bool     exists;
    }

    struct Action {
        address  recorder;
        uint256  timestamp;
        string   description;
    }

    uint256 private _nextSessionId = 1;

    // sessionId => Session
    mapping(uint256 => Session) private _sessions;
    // sessionId => list of Actions
    mapping(uint256 => Action[]) private _actions;

    event RecorderAdded(address indexed account);
    event RecorderRemoved(address indexed account);
    event SessionCreated(uint256 indexed sessionId, string name, uint256 createdAt);
    event ActionRecorded(uint256 indexed sessionId, address indexed recorder, uint256 timestamp, string description);

    modifier onlyRecorder() {
        require(hasRole(RECORDER_ROLE, msg.sender), "Logger: not a recorder");
        _;
    }

    modifier sessionExists(uint256 sessionId) {
        require(_sessions[sessionId].exists, "Logger: session not found");
        _;
    }

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Grant RECORDER_ROLE to an account
    function addRecorder(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(RECORDER_ROLE, account);
        emit RecorderAdded(account);
    }

    /// @notice Revoke RECORDER_ROLE from an account
    function removeRecorder(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(RECORDER_ROLE, account);
        emit RecorderRemoved(account);
    }

    /// @notice Pause logging
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause();
    }

    /// @notice Unpause logging
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Create a new exercise/test session
    /// @param name Human-readable name of the session
    /// @return sessionId Unique identifier for the session
    function createSession(string calldata name)
        external
        whenNotPaused
        onlyRole(DEFAULT_ADMIN_ROLE)
        returns (uint256 sessionId)
    {
        require(bytes(name).length > 0, "Logger: name required");
        sessionId = _nextSessionId++;
        _sessions[sessionId] = Session({
            name:      name,
            createdAt: block.timestamp,
            exists:    true
        });
        emit SessionCreated(sessionId, name, block.timestamp);
    }

    /// @notice Record an action in a session
    /// @param sessionId Identifier of the session
    /// @param description Description of the action/event
    function recordAction(uint256 sessionId, string calldata description)
        external
        whenNotPaused
        onlyRecorder
        sessionExists(sessionId)
    {
        require(bytes(description).length > 0, "Logger: description required");
        _actions[sessionId].push(Action({
            recorder:    msg.sender,
            timestamp:   block.timestamp,
            description: description
        }));
        emit ActionRecorded(sessionId, msg.sender, block.timestamp, description);
    }

    /// @notice Get session metadata
    function getSession(uint256 sessionId)
        external
        view
        sessionExists(sessionId)
        returns (string memory name, uint256 createdAt)
    {
        Session storage s = _sessions[sessionId];
        return (s.name, s.createdAt);
    }

    /// @notice Get all actions recorded in a session
    function getActions(uint256 sessionId)
        external
        view
        sessionExists(sessionId)
        returns (
            address[] memory recorders,
            uint256[] memory timestamps,
            string[]  memory descriptions
        )
    {
        Action[] storage acts = _actions[sessionId];
        uint256 n = acts.length;

        recorders    = new address[](n);
        timestamps   = new uint256[](n);
        descriptions = new string[](n);

        for (uint256 i = 0; i < n; i++) {
            Action storage a = acts[i];
            recorders[i]    = a.recorder;
            timestamps[i]   = a.timestamp;
            descriptions[i] = a.description;
        }
    }
}
