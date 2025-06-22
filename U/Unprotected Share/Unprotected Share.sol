// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UnprotectedShareSuite.sol
/// @notice On‑chain analogues of “Unprotected Share” patterns:
///   Types: FileShare, DirShare, LinkShare  
///   AttackTypes: UnauthorizedAccess, OverrideShare, FloodShare, StaleAccess  
///   DefenseTypes: AccessControl, ImmutableOnce, RateLimit, TTLExpire  

enum ShareType           { FileShare, DirShare, LinkShare }
enum ShareAttackType     { UnauthorizedAccess, OverrideShare, FloodShare, StaleAccess }
enum ShareDefenseType    { AccessControl, ImmutableOnce, RateLimit, TTLExpire }

error US__NotOwner();
error US__AlreadyShared();
error US__TooManyShares();
error US__ShareExpired();

////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED SHARE CREATION
//
//   • Vulnerable: anyone may share any resource
//   • Attack: unauthorized caller lists victim’s data
//   • Defense: AccessControl—only owner may share
////////////////////////////////////////////////////////////////////////
contract UnprotectedShareVuln1 {
    mapping(bytes32 => address) public shares; // resourceId → owner

    function share(bytes32 resourceId) external {
        // ❌ no access control
        shares[resourceId] = msg.sender;
    }
}

contract Attack_UnprotectedShare1 {
    UnprotectedShareVuln1 public target;
    constructor(UnprotectedShareVuln1 _t) { target = _t; }

    function steal(bytes32 resourceId) external {
        // attacker registers share for victim’s resource
        target.share(resourceId);
    }
}

contract UnprotectedShareSafe1 {
    mapping(bytes32 => address) public shares;
    address public owner;
    error US__NotOwner();

    constructor() { owner = msg.sender; }

    function share(bytes32 resourceId) external {
        if (msg.sender != owner) revert US__NotOwner();
        shares[resourceId] = msg.sender;
    }
}

////////////////////////////////////////////////////////////////////////
// 2) OVERRIDE SHARE VULNERABILITY
//
//   • Vulnerable: existing share may be overwritten by anyone
//   • Attack: attacker re‑shares to take over
//   • Defense: ImmutableOnce—first share is permanent
////////////////////////////////////////////////////////////////////////
contract UnprotectedShareVuln2 {
    mapping(bytes32 => address) public shares;

    function share(bytes32 resourceId) external {
        shares[resourceId] = msg.sender;
    }
}

contract Attack_UnprotectedShare2 {
    UnprotectedShareVuln2 public target;
    constructor(UnprotectedShareVuln2 _t) { target = _t; }

    function overrideShare(bytes32 resourceId) external {
        target.share(resourceId);
    }
}

contract UnprotectedShareSafe2 {
    mapping(bytes32 => address) public shares;
    error US__AlreadyShared();

    function share(bytes32 resourceId) external {
        if (shares[resourceId] != address(0)) revert US__AlreadyShared();
        shares[resourceId] = msg.sender;
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SHARE FLOOD (DoS)
//
//   • Vulnerable: no cap on number of shares → storage exhaustion
//   • Attack: attacker floods many share() calls
//   • Defense: RateLimit—cap shares per block
////////////////////////////////////////////////////////////////////////
contract UnprotectedShareVuln3 {
    mapping(bytes32 => address) public shares;

    function share(bytes32 resourceId) external {
        shares[resourceId] = msg.sender;
    }
}

contract Attack_UnprotectedShare3 {
    UnprotectedShareVuln3 public target;
    constructor(UnprotectedShareVuln3 _t) { target = _t; }

    function flood(bytes32[] calldata ids) external {
        for (uint i; i < ids.length; i++) {
            target.share(ids[i]);
        }
    }
}

contract UnprotectedShareSafe3 {
    mapping(bytes32 => address) public shares;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 10;
    error US__TooManyShares();

    function share(bytes32 resourceId) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert US__TooManyShares();
        shares[resourceId] = msg.sender;
    }
}

////////////////////////////////////////////////////////////////////////
// 4) STALE SHARE EXPIRY
//
//   • Vulnerable: shares never expire → stale access persists
//   • Attack: reuse share long after intended lifetime
//   • Defense: TTLExpire—attach expiry and reject expired shares
////////////////////////////////////////////////////////////////////////
contract UnprotectedShareVuln4 {
    mapping(bytes32 => address) public shares;

    function share(bytes32 resourceId) external {
        shares[resourceId] = msg.sender;
    }

    function access(bytes32 resourceId) external view returns (address) {
        return shares[resourceId];
    }
}

contract UnprotectedShareSafe4 {
    struct Share { address who; uint256 expiry; }
    mapping(bytes32 => Share) public shares;
    error US__ShareExpired();

    function share(bytes32 resourceId, uint256 ttl) external {
        shares[resourceId] = Share({ who: msg.sender, expiry: block.timestamp + ttl });
    }

    function access(bytes32 resourceId) external view returns (address) {
        Share memory s = shares[resourceId];
        if (block.timestamp > s.expiry) revert US__ShareExpired();
        return s.who;
    }
}
