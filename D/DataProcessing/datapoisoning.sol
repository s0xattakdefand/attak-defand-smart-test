// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/* ============================================================================
   DATA-POISONING DEMO  –  “Adversary controls part of the training data”
        · Section 1 : BlindDataset                (⚠️ vulnerable)
        · Section 2 : StakingRoles helper
        · Section 3 : PoisonResistantDataset      (✅ hardened)
   ========================================================================== */

/* ----------------------------------------------------------------------------
   SECTION 1  –  VULNERABLE “BlindDataset”
   Stores every sample exactly as submitted; attacker can skew the dataset with
   bogus pairs like  (imageHashOfDog ➜ label = "cat").  No stake, no review,
   no provenance ⇒ perfect target for poisoning.
----------------------------------------------------------------------------- */
contract BlindDataset {
    struct Sample {
        bytes32 featureHash;  // e.g., keccak256(data blob stored off-chain)
        uint16  label;        // class index for ML
        address uploader;
        uint256 timestamp;
    }

    Sample[] public samples;          // raw points – poisonable
    event SampleAdded(uint256 indexed id, bytes32 featureHash, uint16 label);

    /// Anyone can push any sample, no verification
    function add(bytes32 featureHash, uint16 label) external {
        samples.push(Sample(featureHash, label, msg.sender, block.timestamp));
        emit SampleAdded(samples.length - 1, featureHash, label);
    }

    function totalSamples() external view returns (uint256) { return samples.length; }
}

/* ----------------------------------------------------------------------------
   SECTION 2  –  HELPER “StakingRoles”
   Provides:
     · role management (ADMIN, REVIEWER)
     · ERC-20-like minimal staking token with fixed supply
----------------------------------------------------------------------------- */
abstract contract StakingRoles {
    /* ---------- simple ERC-20-ish token for staking ---------- */
    string  public constant name     = "DatasetStake";
    string  public constant symbol   = "DSTK";
    uint8   public constant decimals = 18;
    uint256 public immutable totalSupply;

    mapping(address => uint256) public balanceOf;

    /* ---------- roles ---------- */
    bytes32 public constant ADMIN    = keccak256("ADMIN");
    bytes32 public constant REVIEWER = keccak256("REVIEWER");
    mapping(bytes32 => mapping(address => bool)) internal _roles;

    /* ---------- events ---------- */
    event Transfer(address indexed from, address indexed to, uint256 value);
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    /* ---------- modifiers ---------- */
    modifier onlyRole(bytes32 r) { require(_roles[r][msg.sender], "Forbidden"); _; }

    constructor(uint256 _mintToDeployer) {
        totalSupply = _mintToDeployer;
        balanceOf[msg.sender] = _mintToDeployer;
        emit Transfer(address(0), msg.sender, _mintToDeployer);
        _grant(ADMIN, msg.sender);
    }

    /* ------- ERC-20 transfer (required for stake refunds) ------- */
    function transfer(address to, uint256 value) external returns (bool) {
        balanceOf[msg.sender] -= value;
        balanceOf[to]         += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    /* ---------- role admin API ---------- */
    function grantRole(bytes32 r, address a) external onlyRole(ADMIN) { _grant(r, a); }
    function revokeRole(bytes32 r, address a) external onlyRole(ADMIN) { _revoke(r, a); }

    /* ---------- internal helpers ---------- */
    function _grant(bytes32 r, address a) internal {
        if (!_roles[r][a]) { _roles[r][a] = true; emit RoleGranted(r, a); }
    }
    function _revoke(bytes32 r, address a) internal {
        if (_roles[r][a]) { _roles[r][a] = false; emit RoleRevoked(r, a); }
    }
}

/* ----------------------------------------------------------------------------
   SECTION 3  –  HARDENED “PoisonResistantDataset”
   • Uploaders stake tokens per sample (discouraging spam/poison).  
   • Each sample enters PENDING state → needs ≥ M approvals from REVIEWERs.  
   • Disapproved sample burns uploader stake (slashed).  
   • Approved sample moves to FINAL set used for model training.
----------------------------------------------------------------------------- */
contract PoisonResistantDataset is StakingRoles {
    /* ---------- config ---------- */
    uint256 public constant STAKE_PER_SAMPLE = 10 * 10**18; // 10 DSTK
    uint8   public constant MIN_APPROVALS    = 3;           // M-of-N reviewers

    /* ---------- sample lifecycle ---------- */
    enum Status { NONE, PENDING, APPROVED, REJECTED }

    struct Pending {
        bytes32 featureHash;
        uint16  label;
        address uploader;
        uint8   approvals;
        uint8   rejections;
        Status  status;
    }

    Pending[] public pending;               // index = sampleId
    Sample[]  public finalSet;              // reuses struct from vulnerable

    /* ---------- struct reuse ---------- */
    struct Sample {
        bytes32 featureHash;
        uint16  label;
        address uploader;
        uint256 timestamp;
    }

    /* ---------- events ---------- */
    event PendingAdded(uint256 indexed id, address indexed uploader);
    event Voted(uint256 indexed id, address indexed reviewer, bool approve);
    event Finalized(uint256 indexed id, bool approved);

    constructor()
        StakingRoles(1_000_000 * 10**18)   // mint 1 M DSTK to deployer
    {}

    /* ---------- uploader action ---------- */
    function submit(bytes32 featureHash, uint16 label) external {
        /* stake transfer */
        balanceOf[msg.sender] -= STAKE_PER_SAMPLE;
        balanceOf[address(this)] += STAKE_PER_SAMPLE;
        emit Transfer(msg.sender, address(this), STAKE_PER_SAMPLE);

        pending.push(Pending(
            featureHash,
            label,
            msg.sender,
            0,
            0,
            Status.PENDING
        ));
        emit PendingAdded(pending.length - 1, msg.sender);
    }

    /* ---------- reviewer voting ---------- */
    mapping(uint256 => mapping(address => bool)) public voted; // sampleId → reviewer→voted?

    function vote(uint256 id, bool approve)
        external
        onlyRole(REVIEWER)
    {
        Pending storage p = pending[id];
        require(p.status == Status.PENDING, "Finalized");
        require(!voted[id][msg.sender], "Already voted");
        voted[id][msg.sender] = true;

        if (approve)  p.approvals++;
        else          p.rejections++;

        emit Voted(id, msg.sender, approve);

        /* finalize if quorum reached */
        if (p.approvals >= MIN_APPROVALS) {
            _finalize(id, true);
        } else if (p.rejections >= MIN_APPROVALS) {
            _finalize(id, false);
        }
    }

    /* ---------- internal finalize ---------- */
    function _finalize(uint256 id, bool approved) internal {
        Pending storage p = pending[id];
        p.status = approved ? Status.APPROVED : Status.REJECTED;

        if (approved) {
            finalSet.push(Sample(
                p.featureHash,
                p.label,
                p.uploader,
                block.timestamp
            ));
            /* return stake */
            balanceOf[address(this)] -= STAKE_PER_SAMPLE;
            balanceOf[p.uploader]    += STAKE_PER_SAMPLE;
            emit Transfer(address(this), p.uploader, STAKE_PER_SAMPLE);
        } else {
            /* burn stake by sending to 0x0 */
            balanceOf[address(this)] -= STAKE_PER_SAMPLE;
            emit Transfer(address(this), address(0), STAKE_PER_SAMPLE);
        }
        emit Finalized(id, approved);
    }

    /* ---------- view helpers ---------- */
    function totalFinalSamples() external view returns (uint256) { return finalSet.length; }
    function pendingInfo(uint256 id) external view returns (Pending memory) { return pending[id]; }
}
