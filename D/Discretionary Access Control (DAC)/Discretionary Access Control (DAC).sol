// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title DiscretionaryAccessControlSuite.sol
/// @notice On‑chain analogues of “Discretionary Access Control” patterns:
///   Types: OwnerControlled, ACL, CapabilityBased  
///   AttackTypes: SpoofOwnership, ACLBypass, PrivilegeEscalation  
///   DefenseTypes: ACLCheck, CapabilityValidation, ImmutablePermissions  

enum DiscretionaryAccessControlType       { OwnerControlled, ACL, CapabilityBased }
enum DiscretionaryAccessControlAttackType { SpoofOwnership, ACLBypass, PrivilegeEscalation }
enum DiscretionaryAccessControlDefenseType{ ACLCheck, CapabilityValidation, ImmutablePermissions }

error DAC__NotOwner();
error DAC__Unauthorized();
error DAC__AlreadySet();
error DAC__NoCapability();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE OWNER‑CONTROLLED ACCESS
//
//    • anyone may claim ownership of any resource → SpoofOwnership
////////////////////////////////////////////////////////////////////////
contract DACVuln {
    mapping(uint256 => address) public ownerOf;
    event Accessed(uint256 indexed id, address indexed who, DiscretionaryAccessControlAttackType attack);

    function setOwner(uint256 id, address who) external {
        // ❌ no owner check
        ownerOf[id] = who;
    }

    function access(uint256 id) external {
        // ❌ no authorization check
        emit Accessed(id, msg.sender, DiscretionaryAccessControlAttackType.SpoofOwnership);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • demonstrates spoofing ownership and unauthorized access
////////////////////////////////////////////////////////////////////////
contract Attack_DAC {
    DACVuln public target;
    constructor(DACVuln _t) { target = _t; }

    function spoof(uint256 id) external {
        // attacker claims to be owner
        target.setOwner(id, msg.sender);
        target.access(id);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE OWNER‑ONLY CONTROL
//
//    • Defense: only current owner may transfer ownership
////////////////////////////////////////////////////////////////////////
contract DACSafeOwner {
    mapping(uint256 => address) public ownerOf;
    event Accessed(uint256 indexed id, address indexed who, DiscretionaryAccessControlDefenseType defense);

    constructor() {
        // optionally assign deployer as owner of resource 0
        ownerOf[0] = msg.sender;
    }

    function setOwner(uint256 id, address who) external {
        if (ownerOf[id] != msg.sender) revert DAC__NotOwner();
        ownerOf[id] = who;
    }

    function access(uint256 id) external {
        // still no fine‑grained ACL, but owner check applies to transfers only
        emit Accessed(id, msg.sender, DiscretionaryAccessControlDefenseType.ACLCheck);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE ACL‑BASED CONTROL
//
//    • Defense: ACLCheck – maintain list of authorized users per resource
////////////////////////////////////////////////////////////////////////
contract DACSafeACL {
    mapping(uint256 => mapping(address => bool)) public acl;
    mapping(uint256 => address) public ownerOf;
    address public deployer;

    event Accessed(uint256 indexed id, address indexed who, DiscretionaryAccessControlDefenseType defense);

    error DAC__NotAllowed();

    constructor() {
        deployer = msg.sender;
    }

    function setOwner(uint256 id, address who) external {
        // only deployer may initially assign owners
        if (msg.sender != deployer) revert DAC__NotOwner();
        ownerOf[id] = who;
    }

    function grant(uint256 id, address who) external {
        if (msg.sender != ownerOf[id]) revert DAC__NotOwner();
        acl[id][who] = true;
    }

    function revoke(uint256 id, address who) external {
        if (msg.sender != ownerOf[id]) revert DAC__NotOwner();
        acl[id][who] = false;
    }

    function access(uint256 id) external {
        if (!acl[id][msg.sender]) revert DAC__Unauthorized();
        emit Accessed(id, msg.sender, DiscretionaryAccessControlDefenseType.ACLCheck);
    }
}

////////////////////////////////////////////////////////////////////////
// 5) SAFE CAPABILITY‑BASED CONTROL WITH IMMUTABLE PERMISSIONS
//
//    • Defense: CapabilityValidation + ImmutablePermissions  
////////////////////////////////////////////////////////////////////////
contract DACSafeCapability {
    mapping(uint256 => mapping(bytes32 => bool)) public caps; // resourceId → capability token → valid
    mapping(uint256 => bool) public initialized;
    event Accessed(uint256 indexed id, address indexed who, DiscretionaryAccessControlDefenseType defense);

    error DAC__CapInvalid();
    error DAC__AlreadyInit();

    /// initialize capabilities for a resource once
    function initialize(uint256 id, bytes32[] calldata tokens) external {
        if (initialized[id]) revert DAC__AlreadySet();
        initialized[id] = true;
        for (uint i = 0; i < tokens.length; i++) {
            caps[id][tokens[i]] = true;
        }
    }

    /// present a valid capability token to gain access
    function accessWithCap(uint256 id, bytes32 token) external {
        if (!initialized[id] || !caps[id][token]) revert DAC__NoCapability();
        emit Accessed(id, msg.sender, DiscretionaryAccessControlDefenseType.CapabilityValidation);
    }
}
