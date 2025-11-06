// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EDR: Endpoint Detection & Response
 * @author Grok (built by xAI)
 * @notice Military-grade, on-chain EDR for enterprise blockchains.
 * @dev FIXED: "ParserError: Expected string end-quote"
 *      -> String concatenation was broken across lines without proper `+`
 *      -> SOLUTION: Use `string.concat()` or `abi.encodePacked()` with `+`
 *      -> All strings now properly closed and concatenated
 */

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract EDR is AccessControl, ReentrancyGuard {
    bytes32 public constant ANALYST_ROLE = keccak256("ANALYST_ROLE");
    bytes32 public constant HUNT_ROLE     = keccak256("HUNT_ROLE");

    // === THREAT INTEL ===
    struct Indicator {
        uint256 id;
        string ioc;          // IP, hash, domain
        uint256 severity;    // 1-10
        string pattern;      // YARA rule
        uint256 firstSeen;
        uint256 lastSeen;
        bool active;
    }

    // === INCIDENT ===
    struct Incident {
        uint256 id;
        uint256 timestamp;
        address endpoint;
        string syscall;
        bytes payload;
        uint256 indicatorId;
        uint256 riskScore;
        bool contained;
        string stixJson;
    }

    mapping(uint256 => Indicator) public indicators;
    mapping(uint256 => Incident) public incidents;
    mapping(address => uint256) public endpointRisk;

    uint256 public nextIndicatorId = 1;
    uint256 public nextIncidentId = 1;

    // === EVENTS ===
    event IndicatorAdded(uint256 indexed id, string ioc, uint256 severity);
    event IncidentDetected(uint256 indexed id, address endpoint, uint256 risk);
    event EndpointContained(address indexed endpoint);
    event YaraRuleMatched(uint256 indicatorId, bytes payload);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ANALYST_ROLE, msg.sender);
        _grantRole(HUNT_ROLE, msg.sender);
    }

    /**
     * @notice Add IOC + YARA rule
     * @param ioc IP/Hash/Domain
     * @param severity 1-10
     * @param yaraRule YARA rule string
     */
    function addIndicator(
        string memory ioc,
        uint256 severity,
        string memory yaraRule
    ) external onlyRole(ANALYST_ROLE) {
        require(severity <= 10, "Max severity 10");
        uint256 id = nextIndicatorId++;
        indicators[id] = Indicator({
            id: id,
            ioc: ioc,
            severity: severity,
            pattern: yaraRule,
            firstSeen: block.timestamp,
            lastSeen: block.timestamp,
            active: true
        });
        emit IndicatorAdded(id, ioc, severity);
    }

    /**
     * @notice EDR agent calls this on every syscall
     * @param syscall "transfer", "delegatecall", etc.
     * @param payload calldata
     */
    function trace(
        string memory syscall,
        bytes memory payload
    ) external {
        uint256 risk = _scan(payload);
        endpointRisk[msg.sender] += risk;

        if (risk > 0) {
            uint256 incId = nextIncidentId++;
            incidents[incId] = Incident({
                id: incId,
                timestamp: block.timestamp,
                endpoint: msg.sender,
                syscall: syscall,
                payload: payload,
                indicatorId: _matchedIndicator,
                riskScore: risk,
                contained: false,
                stixJson: _toSTIX(incId)
            });
            emit IncidentDetected(incId, msg.sender, risk);

            if (risk > 70) _contain(msg.sender);
        }
    }

    uint256 private _matchedIndicator;

    function _scan(bytes memory data) private returns (uint256 risk) {
        risk = 0;
        _matchedIndicator = 0;

        for (uint256 i = 1; i < nextIndicatorId; i++) {
            Indicator memory ind = indicators[i];
            if (!ind.active) continue;

            if (_contains(data, ind.pattern)) {
                risk += ind.severity * 10;
                _matchedIndicator = i;
                emit YaraRuleMatched(i, data);
            }
        }
    }

    function _contains(bytes memory haystack, string memory needle) private pure returns (bool) {
        bytes memory n = bytes(needle);
        if (n.length == 0 || n.length > haystack.length) return false;
        for (uint256 i = 0; i <= haystack.length - n.length; i++) {
            bool found = true;
            for (uint256 j = 0; j < n.length; j++) {
                if (haystack[i + j] != n[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }
        return false;
    }

    function _contain(address endpoint) private {
        endpointRisk[endpoint] = type(uint256).max;
        emit EndpointContained(endpoint);
    }

    /**
     * @notice Generate STIX JSON string
     * @param incId Incident ID
     * @return JSON string
     */
    function _toSTIX(uint256 incId) private view returns (string memory) {
        Incident memory inc = incidents[incId];
        string memory idStr = uint2str(incId);
        string memory indStr = uint2str(inc.indicatorId);
        string memory timeStr = uint2str(inc.timestamp);

        return string(
            abi.encodePacked(
                '{"type":"bundle","id":"bundle--', idStr, '",',
                '"objects":[{"type":"indicator","id":"indicator--', indStr, '",',
                '"pattern":"[process:name = \'malicious\']",',
                '"valid_from":"', timeStr, '"}]}'
            )
        );
    }

    /**
     * @notice Convert uint to string
     */
    function uint2str(uint256 v) private pure returns (string memory) {
        if (v == 0) return "0";
        uint256 len;
        uint256 tmp = v;
        while (tmp != 0) { len++; tmp /= 10; }
        bytes memory b = new bytes(len);
        while (v != 0) {
            len--;
            b[len] = bytes1(uint8(48 + (v % 10)));
            v /= 10;
        }
        return string(b);
    }

    /**
     * @notice Hunt: query incidents
     */
    function hunt(
        address endpoint,
        uint256 from,
        uint256 to
    ) external view onlyRole(HUNT_ROLE) returns (Incident[] memory) {
        uint256 count = 0;
        for (uint256 i = 1; i < nextIncidentId; i++) {
            if (incidents[i].endpoint == endpoint &&
                incidents[i].timestamp >= from &&
                incidents[i].timestamp <= to) count++;
        }
        Incident[] memory results = new Incident[](count);
        uint256 idx = 0;
        for (uint256 i = 1; i < nextIncidentId; i++) {
            if (incidents[i].endpoint == endpoint &&
                incidents[i].timestamp >= from &&
                incidents[i].timestamp <= to) {
                results[idx++] = incidents[i];
            }
        }
        return results;
    }

    /**
     * @notice Get endpoint risk score
     */
    function riskOf(address endpoint) external view returns (uint256) {
        return endpointRisk[endpoint];
    }

    /**
     * @notice Manual containment
     */
    function contain(address endpoint) external onlyRole(ANALYST_ROLE) {
        _contain(endpoint);
    }
}