// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB:
 *
 * "Enhanced Feasible Path Unicast Reverse Path Forwarding"
 *
 * We model a simplified on-chain Reverse Path Forwarding (RPF) registry:
 *
 *  - prefixId: bytes32 identifier for a unicast prefix (e.g., hash of "10.0.0.0/24")
 *  - feasiblePaths: candidate next-hop addresses that can be used to reach that prefix
 *  - bestPath: chosen best/primary next-hop
 *  - enhancedFeasible: mark a path as "enhanced feasible" (allowed for RPF checks)
 *
 * INSECURE:
 *  - Anyone can register prefixes & paths
 *  - Anyone can mark paths as enhanced feasible
 *  - RPF validation can be trivially bypassed/spoofed
 *
 * SECURE:
 *  - Owner (admin) controls prefix/paths
 *  - Constraints on who can add/approve paths
 *  - RPF check only passes for admin-approved enhanced feasible paths
 */

/*//////////////////////////////////////////////////////////////
//                   INSECURE RPF VERSION
//////////////////////////////////////////////////////////////*/

contract EnhancedRPFInsecure {
    struct PathInfo {
        address nextHop;         // next-hop router (modeled as address)
        uint256 metric;          // cost/metric
        bool feasible;           // normal feasible path
        bool enhancedFeasible;   // enhanced feasible path (whitelisted)
    }

    struct Prefix {
        bytes32 prefixId;        // identifier of the prefix
        address bestPath;        // chosen best next-hop
        PathInfo[] paths;        // candidate feasible/enhanced feasible paths
        bool exists;
    }

    // prefixId => Prefix
    mapping(bytes32 => Prefix) public prefixes;

    event PrefixRegistered(bytes32 indexed prefixId);
    event PathAdded(bytes32 indexed prefixId, address indexed nextHop, uint256 metric);
    event BestPathSet(bytes32 indexed prefixId, address indexed bestPath);
    event PathEnhanced(bytes32 indexed prefixId, address indexed nextHop, bool enhanced);

    /**
     * ⚠️ VULN #1:
     * Anyone can register any prefixId.
     */
    function registerPrefix(bytes32 prefixId) external {
        Prefix storage p = prefixes[prefixId];
        p.prefixId = prefixId;
        p.exists = true;

        emit PrefixRegistered(prefixId);
    }

    /**
     * ⚠️ VULN #2:
     * Anyone can add a path to any prefix, with arbitrary metric.
     */
    function addPath(
        bytes32 prefixId,
        address nextHop,
        uint256 metric,
        bool feasible
    ) external {
        require(prefixes[prefixId].exists, "PREFIX_NOT_EXIST");

        prefixes[prefixId].paths.push(
            PathInfo({
                nextHop: nextHop,
                metric: metric,
                feasible: feasible,
                enhancedFeasible: false
            })
        );

        emit PathAdded(prefixId, nextHop, metric);
    }

    /**
     * ⚠️ VULN #3:
     * Anyone can set the best path, no constraints.
     */
    function setBestPath(bytes32 prefixId, address bestPath) external {
        require(prefixes[prefixId].exists, "PREFIX_NOT_EXIST");
        prefixes[prefixId].bestPath = bestPath;

        emit BestPathSet(prefixId, bestPath);
    }

    /**
     * ⚠️ VULN #4:
     * Anyone can mark any path as enhanced feasible.
     */
    function setEnhancedFeasible(
        bytes32 prefixId,
        uint256 pathIndex,
        bool enhanced
    ) external {
        Prefix storage p = prefixes[prefixId];
        require(p.exists, "PREFIX_NOT_EXIST");
        require(pathIndex < p.paths.length, "BAD_INDEX");

        p.paths[pathIndex].enhancedFeasible = enhanced;

        emit PathEnhanced(prefixId, p.paths[pathIndex].nextHop, enhanced);
    }

    /**
     * Basic RPF check:
     *   - Given srcPrefixId and incomingNextHop,
     *   - returns true if there exists an enhanced feasible path with that nextHop.
     *
     * But all the inputs (prefix, paths, enhanced flags) are attacker-controlled.
     */
    function isValidReversePath(
        bytes32 srcPrefixId,
        address incomingNextHop
    ) external view returns (bool) {
        Prefix storage p = prefixes[srcPrefixId];
        if (!p.exists) return false;

        for (uint256 i = 0; i < p.paths.length; i++) {
            PathInfo storage info = p.paths[i];
            if (
                info.nextHop == incomingNextHop &&
                info.enhancedFeasible
            ) {
                return true;
            }
        }

        return false;
    }
}

/*//////////////////////////////////////////////////////////////
//                          OWNABLE
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
//                  SECURE / DEFENDED RPF VERSION
//////////////////////////////////////////////////////////////*/

contract EnhancedRPFSecure is Ownable {
    struct PathInfo {
        address nextHop;
        uint256 metric;
        bool feasible;
        bool enhancedFeasible;
    }

    struct Prefix {
        bytes32 prefixId;
        address bestPath;
        PathInfo[] paths;
        bool exists;
    }

    mapping(bytes32 => Prefix) public prefixes;

    // Optional: registered router addresses that are allowed as next-hops
    mapping(address => bool) public isRegisteredRouter;

    event RouterRegistered(address indexed router, bool allowed);
    event PrefixRegistered(bytes32 indexed prefixId);
    event PathAdded(bytes32 indexed prefixId, address indexed nextHop, uint256 metric);
    event BestPathSet(bytes32 indexed prefixId, address indexed bestPath);
    event PathEnhanced(bytes32 indexed prefixId, address indexed nextHop, bool enhanced);

    /**
     * Admin registers a router address as a valid next-hop.
     */
    function setRouter(address router, bool allowed) external onlyOwner {
        require(router != address(0), "ZERO_ROUTER");
        isRegisteredRouter[router] = allowed;
        emit RouterRegistered(router, allowed);
    }

    /**
     * Admin registers a new prefix.
     */
    function registerPrefix(bytes32 prefixId) external onlyOwner {
        Prefix storage p = prefixes[prefixId];
        require(!p.exists, "PREFIX_EXISTS");

        p.prefixId = prefixId;
        p.exists = true;

        emit PrefixRegistered(prefixId);
    }

    /**
     * Admin adds a path for a prefix.
     * Enforces that nextHop is a registered router and metric is non-zero.
     */
    function addPath(
        bytes32 prefixId,
        address nextHop,
        uint256 metric,
        bool feasible
    ) external onlyOwner {
        Prefix storage p = prefixes[prefixId];
        require(p.exists, "PREFIX_NOT_EXIST");
        require(isRegisteredRouter[nextHop], "ROUTER_NOT_REGISTERED");
        require(metric > 0, "BAD_METRIC");

        p.paths.push(
            PathInfo({
                nextHop: nextHop,
                metric: metric,
                feasible: feasible,
                enhancedFeasible: false
            })
        );

        emit PathAdded(prefixId, nextHop, metric);
    }

    /**
     * Admin chooses the best path among registered paths.
     */
    function setBestPath(
        bytes32 prefixId,
        address bestPath
    ) external onlyOwner {
        Prefix storage p = prefixes[prefixId];
        require(p.exists, "PREFIX_NOT_EXIST");
        require(isRegisteredRouter[bestPath], "ROUTER_NOT_REGISTERED");

        // Optional: verify bestPath exists in paths list
        bool found;
        for (uint256 i = 0; i < p.paths.length; i++) {
            if (p.paths[i].nextHop == bestPath) {
                found = true;
                break;
            }
        }
        require(found, "BEST_NOT_IN_FEASIBLE_SET");

        p.bestPath = bestPath;
        emit BestPathSet(prefixId, bestPath);
    }

    /**
     * Admin sets a path as enhanced feasible.
     * Only allowed on existing feasible paths.
     */
    function setEnhancedFeasible(
        bytes32 prefixId,
        uint256 pathIndex,
        bool enhanced
    ) external onlyOwner {
        Prefix storage p = prefixes[prefixId];
        require(p.exists, "PREFIX_NOT_EXIST");
        require(pathIndex < p.paths.length, "BAD_INDEX");

        PathInfo storage info = p.paths[pathIndex];
        require(info.feasible, "NOT_FEASIBLE");

        info.enhancedFeasible = enhanced;
        emit PathEnhanced(prefixId, info.nextHop, enhanced);
    }

    /**
     * Secure RPF check:
     *   - Prefix must exist
     *   - incomingNextHop must be a registered router
     *   - Must be an enhanced feasible path for this prefix
     *   - Optionally, bestPath must also be a valid router (sanity)
     */
    function isValidReversePath(
        bytes32 srcPrefixId,
        address incomingNextHop
    ) external view returns (bool) {
        Prefix storage p = prefixes[srcPrefixId];
        if (!p.exists) return false;
        if (!isRegisteredRouter[incomingNextHop]) return false;

        bool foundEnhanced = false;

        for (uint256 i = 0; i < p.paths.length; i++) {
            PathInfo storage info = p.paths[i];
            if (
                info.nextHop == incomingNextHop &&
                info.enhancedFeasible
            ) {
                foundEnhanced = true;
                break;
            }
        }

        return foundEnhanced;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract EnhancedRPFAttacker {
    EnhancedRPFInsecure public target;

    constructor(address _target) {
        target = EnhancedRPFInsecure(_target);
    }

    /**
     * Attack step #1:
     * Register a fake unicast prefix.
     */
    function spoofPrefix(bytes32 prefixId) public {
        target.registerPrefix(prefixId);
    }

    /**
     * Attack step #2:
     * Add a malicious path for that prefix.
     */
    function addMaliciousPath(bytes32 prefixId, address maliciousNextHop) public {
        // metric can be 1 (best), feasible = true
        target.addPath(prefixId, maliciousNextHop, 1, true);
    }

    /**
     * Attack step #3:
     * Mark the malicious path as enhanced feasible.
     */
    function enhanceMaliciousPath(
        bytes32 prefixId,
        uint256 pathIndex
    ) public {
        target.setEnhancedFeasible(prefixId, pathIndex, true);
    }

    /**
     * Full attack:
     *  - spoof prefix
     *  - add malicious path
     *  - mark as enhanced feasible
     *
     * After this, calls to isValidReversePath(prefixId, maliciousNextHop)
     * will return true on the insecure contract.
     */
    function fullAttack(
        bytes32 prefixId,
        address maliciousNextHop
    ) external {
        spoofPrefix(prefixId);
        addMaliciousPath(prefixId, maliciousNextHop);
        // Assume newly added path is at last index (paths.length - 1),
        // but since we only add once, index 0 is fine for demo.
        enhanceMaliciousPath(prefixId, 0);
    }
}
