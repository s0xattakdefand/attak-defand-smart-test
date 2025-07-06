// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ======================================================================
   CNSSI-4009-2015  &  NIST SP-800-53 r5   —   DATA-MINING DEMO
   ----------------------------------------------------------------------
     · Section 1 : OpenAnalyticsVault        (⚠️ vulnerable)
     · Section 2 : RBAC                      (helper)
     · Section 3 : SafeAggregatedAnalytics   (✅ hardened)
   ====================================================================== */

/* ----------------------------------------------------------------------
   SECTION 1  —  VULNERABLE “OpenAnalyticsVault”
   Anyone can push detailed telemetry; everything is public on-chain
   and in event logs → perfect fodder for data-mining.
   -------------------------------------------------------------------- */
contract OpenAnalyticsVault {
    struct Sample {
        uint256 age;
        uint256 salary;
        string  department;
        address reporter;
        uint256 timestamp;
    }

    mapping(uint256 => Sample) public samples; // data-at-rest is raw
    uint256 public sampleCounter;

    event SampleSubmitted(                  // data-in-motion leaked
        uint256 indexed id,
        uint256 age,
        uint256 salary,
        string  department,
        address indexed reporter
    );

    /// Anyone can record a detailed sample (no access control)
    function submit(uint256 age, uint256 salary, string calldata dept) external {
        samples[sampleCounter] = Sample(age, salary, dept, msg.sender, block.timestamp);
        emit SampleSubmitted(sampleCounter, age, salary, dept, msg.sender);
        sampleCounter++;
    }
}

/* ----------------------------------------------------------------------
   SECTION 2  —  MINIMAL ROLE-BASED ACCESS CONTROL
   Internal `_grant` / `_revoke` so derived contracts can reuse them.
   -------------------------------------------------------------------- */
abstract contract RBAC {
    bytes32 public constant ADMIN     = keccak256("ADMIN");
    bytes32 public constant COLLECTOR = keccak256("COLLECTOR"); // allowed to ingest
    bytes32 public constant ANALYST   = keccak256("ANALYST");   // allowed to query

    mapping(bytes32 => mapping(address => bool)) internal _roles;

    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    modifier onlyRole(bytes32 r) {
        require(_roles[r][msg.sender], "RBAC: access denied");
        _;
    }

    constructor() {
        _grant(ADMIN, msg.sender); // deployer is super-admin
    }

    /* ---------- admin API ---------- */
    function grantRole(bytes32 r, address a) external onlyRole(ADMIN) { _grant(r, a); }
    function revokeRole(bytes32 r, address a) external onlyRole(ADMIN) { _revoke(r, a); }
    function hasRole(bytes32 r, address a) public view returns (bool) { return _roles[r][a]; }

    /* ---------- internal helpers ---------- */
    function _grant(bytes32 r, address a) internal {
        if (!_roles[r][a]) { _roles[r][a] = true; emit RoleGranted(r, a); }
    }
    function _revoke(bytes32 r, address a) internal {
        if (_roles[r][a]) { _roles[r][a] = false; emit RoleRevoked(r, a); }
    }
}

/* ----------------------------------------------------------------------
   SECTION 3  —  HARDENED “SafeAggregatedAnalytics”
   • Keeps only aggregate stats (count & salary-sum) per 5-year age-bucket
     and department string.
   • Enforces k-anonymity (≥ K_THRESHOLD samples required before release).
   • Roles:
       – COLLECTOR  : feed data.
       – ANALYST    : run aggregate queries.
   -------------------------------------------------------------------- */
contract SafeAggregatedAnalytics is RBAC {
    /* ----------- configuration ----------- */
    uint256 public constant K_THRESHOLD = 5;   // minimum records per bucket

    /* ----------- internal state ----------- */
    struct Stats { uint64 count; uint256 sumSalary; }
    mapping(bytes32 => Stats) private _bucketStats;  // bucketId → Stats

    event SampleIngested(bytes32 indexed bucketId, uint64 newCount);

    /* ----------- public helpers ----------- */

    /// Hashes (age bucket, department) into a bucket ID.
    /// Age bucket = age / 5  → 0-4, 5-9, 10-14, …
    function bucketId(uint256 age, string calldata dept)
        public
        pure
        returns (bytes32)
    {
        uint256 ageBucket = age / 5;
        return keccak256(abi.encodePacked(ageBucket, dept));
    }

    /* ----------- COLLECTOR API ----------- */

    /// Ingest a single sample (only aggregate stats stored)
    function submit(uint256 age, uint256 salary, string calldata dept)
        external
        onlyRole(COLLECTOR)
    {
        bytes32 b = bucketId(age, dept);
        Stats storage s = _bucketStats[b];
        s.count      += 1;
        s.sumSalary  += salary;
        emit SampleIngested(b, s.count);
    }

    /* ----------- ANALYST API ----------- */

    /// Returns average salary for a (age-bucket, dept) if k-anonymous.
    function averageSalary(uint256 age, string calldata dept)
        external
        view
        onlyRole(ANALYST)
        returns (uint256 avg)
    {
        bytes32 b = bucketId(age, dept);
        Stats storage s = _bucketStats[b];
        require(s.count >= K_THRESHOLD, "Insufficient sample size");
        avg = s.sumSalary / s.count;
    }

    /// Returns raw stats (count & sum) – still respects k-anonymity
    function stats(uint256 age, string calldata dept)
        external
        view
        onlyRole(ANALYST)
        returns (uint64 count, uint256 sumSalary)
    {
        bytes32 b = bucketId(age, dept);
        Stats storage s = _bucketStats[b];
        require(s.count >= K_THRESHOLD, "Insufficient sample size");
        return (s.count, s.sumSalary);
    }
}

/* ======================================================================
   WHY THIS MITIGATES DATA-MINING RISKS
   ----------------------------------------------------------------------
   • **No raw records on-chain** – only (count, sum) per bucket, so an
     attacker cannot correlate individual attributes or re-identify users.
   • **k-Anonymity** – queries revert unless a bucket has ≥ 5 samples,
     blocking high-granularity pattern discovery.
   • **Role separation** – only trusted collectors can ingest, and only
     analysts can query aggregates, giving you centralised governance.
   • **Minimal telemetry in events** – `SampleIngested` discloses only the
     bucket ID and new count, not the actual data values.
   • **Scalable** – gas cost grows with unique buckets, not with every user
     sample, making it more affordable than storing full telemetry.
   ====================================================================== */
