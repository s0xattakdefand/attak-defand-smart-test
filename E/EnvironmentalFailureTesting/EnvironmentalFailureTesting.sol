// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "Environmental Failure Testing"
 *
 * Concept:
 *  - You define test plans for environmental zones (server rooms, data centers, racks).
 *  - You execute tests (power cut, over-temp, humidity spike, etc.).
 *  - You record results (pass/fail, notes, tester).
 *
 * INSECURE CONTRACT:
 *  - Anyone can create/modify test plans.
 *  - Anyone can mark tests as passed.
 *  - Anyone can rewrite results.
 *  - Aggregated "healthy" status is fully attacker-controlled.
 *
 * SECURE CONTRACT:
 *  - Owner defines/locks test plans (what must be tested).
 *  - Only authorized testers can record results.
 *  - Plans can be locked so they can't be modified.
 *  - Zone health derives from locked plans + trusted results.
 */

/*//////////////////////////////////////////////////////////////
//              INSECURE ENV FAILURE TESTING
//////////////////////////////////////////////////////////////*/

contract EnvironmentalFailureTestingInsecure {
    struct TestPlan {
        bytes32 zoneId;         // e.g. keccak256("DC1-ROOM-A")
        string description;     // "Power-off failover test"
        uint256 createdAt;
        bool active;
    }

    struct TestResult {
        bool executed;
        bool passed;
        string notes;
        uint256 executedAt;
        address tester;
    }

    // testId => TestPlan
    mapping(uint256 => TestPlan) public testPlans;

    // testId => TestResult
    mapping(uint256 => TestResult) public testResults;

    event TestPlanCreated(uint256 indexed testId, bytes32 indexed zoneId, string description);
    event TestPlanUpdated(uint256 indexed testId, bool active);
    event TestResultRecorded(uint256 indexed testId, bool passed, string notes, address tester);
    event AllMarkedGreen(bytes32 indexed zoneId);

    /**
     * ⚠️ VULN #1:
     * Anyone can create or overwrite test plans.
     */
    function createOrUpdateTestPlan(
        uint256 testId,
        bytes32 zoneId,
        string calldata description,
        bool active
    ) external {
        testPlans[testId] = TestPlan({
            zoneId: zoneId,
            description: description,
            createdAt: block.timestamp,
            active: active
        });

        emit TestPlanCreated(testId, zoneId, description);
        emit TestPlanUpdated(testId, active);
    }

    /**
     * ⚠️ VULN #2:
     * Anyone can toggle active flag for any test.
     */
    function setTestActive(uint256 testId, bool active) external {
        testPlans[testId].active = active;
        emit TestPlanUpdated(testId, active);
    }

    /**
     * ⚠️ VULN #3:
     * Anyone can record or overwrite test results for any test.
     */
    function recordResult(
        uint256 testId,
        bool passed,
        string calldata notes
    ) external {
        testResults[testId] = TestResult({
            executed: true,
            passed: passed,
            notes: notes,
            executedAt: block.timestamp,
            tester: msg.sender
        });

        emit TestResultRecorded(testId, passed, notes, msg.sender);
    }

    /**
     * ⚠️ VULN #4:
     * One function to mark ALL tests in a zone as "green" by just
     * writing pass results without actually executing anything.
     */
    function markAllGreenForZone(bytes32 zoneId, uint256[] calldata testIds) external {
        for (uint256 i = 0; i < testIds.length; i++) {
            uint256 id = testIds[i];
            if (testPlans[id].zoneId == zoneId) {
                testResults[id] = TestResult({
                    executed: true,
                    passed: true,
                    notes: "Forced green by arbitrary caller",
                    executedAt: block.timestamp,
                    tester: msg.sender
                });

                emit TestResultRecorded(id, true, "Forced green", msg.sender);
            }
        }

        emit AllMarkedGreen(zoneId);
    }

    /**
     * Naive, attacker-controlled zone health:
     *   - If all ACTIVE tests for zone have result.passed == true, returns true.
     */
    function isZoneHealthy(bytes32 zoneId, uint256[] calldata testIds) external view returns (bool) {
        for (uint256 i = 0; i < testIds.length; i++) {
            uint256 id = testIds[i];
            TestPlan storage p = testPlans[id];
            if (p.zoneId != zoneId || !p.active) {
                continue;
            }

            TestResult storage r = testResults[id];
            if (!r.executed || !r.passed) {
                return false;
            }
        }
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
//               SECURE ENV FAILURE TESTING
//////////////////////////////////////////////////////////////*/

contract EnvironmentalFailureTestingSecure is Ownable {
    struct TestPlan {
        bytes32 zoneId;
        string description;
        uint256 createdAt;
        bool active;
        bool locked;       // once locked, cannot change description/zone
        bool exists;
    }

    struct TestResult {
        bool executed;
        bool passed;
        string notes;
        uint256 executedAt;
        address tester;
    }

    // testId => TestPlan
    mapping(uint256 => TestPlan) public testPlans;

    // testId => TestResult
    mapping(uint256 => TestResult) public testResults;

    // authorized testers (SRE / ops, etc.)
    mapping(address => bool) public isTester;

    event TesterSet(address indexed tester, bool allowed);
    event TestPlanCreated(uint256 indexed testId, bytes32 indexed zoneId, string description);
    event TestPlanActivated(uint256 indexed testId, bool active);
    event TestPlanLocked(uint256 indexed testId);
    event TestResultRecorded(uint256 indexed testId, bool passed, string notes, address tester);

    modifier onlyTester() {
        require(isTester[msg.sender], "NOT_TESTER");
        _;
    }

    /**
     * Admin configures which addresses are allowed to run tests.
     */
    function setTester(address tester, bool allowed) external onlyOwner {
        require(tester != address(0), "ZERO_ADDRESS");
        isTester[tester] = allowed;
        emit TesterSet(tester, allowed);
    }

    /**
     * Owner defines a test plan for a zone.
     */
    function createTestPlan(
        uint256 testId,
        bytes32 zoneId,
        string calldata description,
        bool active
    ) external onlyOwner {
        TestPlan storage p = testPlans[testId];
        require(!p.exists, "TEST_EXISTS");

        p.zoneId = zoneId;
        p.description = description;
        p.createdAt = block.timestamp;
        p.active = active;
        p.locked = false;
        p.exists = true;

        emit TestPlanCreated(testId, zoneId, description);
        emit TestPlanActivated(testId, active);
    }

    /**
     * Owner can change active flag for a test plan (enable/disable),
     * but not after locking.
     */
    function setTestActive(uint256 testId, bool active) external onlyOwner {
        TestPlan storage p = testPlans[testId];
        require(p.exists, "TEST_NOT_FOUND");
        require(!p.locked, "TEST_LOCKED");

        p.active = active;
        emit TestPlanActivated(testId, active);
    }

    /**
     * Once locked, zoneId and description & active flag can't be modified.
     * This freezes the test "contract" for audit / compliance.
     */
    function lockTestPlan(uint256 testId) external onlyOwner {
        TestPlan storage p = testPlans[testId];
        require(p.exists, "TEST_NOT_FOUND");
        require(!p.locked, "ALREADY_LOCKED");

        p.locked = true;
        emit TestPlanLocked(testId);
    }

    /**
     * Authorized testers record results for a specific testId.
     * - Test must exist and be active.
     * - Result is overwritten, but always attributed to the last tester.
     * - You can extend with "append-only" pattern if desired.
     */
    function recordResult(
        uint256 testId,
        bool passed,
        string calldata notes
    ) external onlyTester {
        TestPlan storage p = testPlans[testId];
        require(p.exists, "TEST_NOT_FOUND");
        require(p.active, "TEST_NOT_ACTIVE");

        testResults[testId] = TestResult({
            executed: true,
            passed: passed,
            notes: notes,
            executedAt: block.timestamp,
            tester: msg.sender
        });

        emit TestResultRecorded(testId, passed, notes, msg.sender);
    }

    /**
     * Secure zone health check:
     *   - Only considers tests that:
     *       * exist
     *       * are locked (finalized spec)
     *       * are active
     *   - All such tests must be executed and passed.
     */
    function isZoneHealthy(bytes32 zoneId, uint256[] calldata testIds) external view returns (bool) {
        for (uint256 i = 0; i < testIds.length; i++) {
            uint256 id = testIds[i];
            TestPlan storage p = testPlans[id];

            if (!p.exists || !p.locked || !p.active) {
                // ignore non-existent or unlocked/inactive tests
                continue;
            }
            if (p.zoneId != zoneId) {
                continue;
            }

            TestResult storage r = testResults[id];
            if (!r.executed || !r.passed) {
                return false;
            }
        }

        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                          ATTACKER
//////////////////////////////////////////////////////////////*/

contract EnvironmentalFailureTestingAttacker {
    EnvironmentalFailureTestingInsecure public target;

    constructor(address _target) {
        target = EnvironmentalFailureTestingInsecure(_target);
    }

    /**
     * Attack #1:
     * Create fake test plans for a zone with IDs you control.
     */
    function createFakePlans(
        bytes32 zoneId,
        uint256[] calldata testIds,
        string calldata fakeDescription
    ) public {
        for (uint256 i = 0; i < testIds.length; i++) {
            target.createOrUpdateTestPlan(
                testIds[i],
                zoneId,
                fakeDescription,
                true
            );
        }
    }

    /**
     * Attack #2:
     * Force all those tests to appear as passing without doing real tests.
     */
    function markAllGreen(
        bytes32 zoneId,
        uint256[] calldata testIds
    ) public {
        target.markAllGreenForZone(zoneId, testIds);
    }

    /**
     * Attack #3:
     * For any real test that failed, overwrite the result to passed.
     */
    function overwriteResult(uint256 testId, string calldata fakeNotes) public {
        target.recordResult(testId, true, fakeNotes);
    }

    /**
     * One-click scenario:
     *  - Create fake plans
     *  - Mark them green
     * After this, isZoneHealthy on the insecure contract may say "true".
     */
    function fullAttack(
        bytes32 zoneId,
        uint256[] calldata testIds,
        string calldata fakeDescription
    ) external {
        createFakePlans(zoneId, testIds, fakeDescription);
        markAllGreen(zoneId, testIds);
    }
}
