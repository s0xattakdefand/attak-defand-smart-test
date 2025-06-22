// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AccessControlServiceSuite.sol
/// @notice On‑chain analogues of “Access Control Service” patterns:
///   Types: Centralized, TokenBased, PolicyBased  
///   AttackTypes: Bypass, Replay, TokenTheft, Misconfiguration  
///   DefenseTypes: Auth, TokenValidation, PolicyEnforcement, Revocation  

enum AccessControlServiceType       { Centralized, TokenBased, PolicyBased }
enum AccessControlServiceAttackType { Bypass, Replay, TokenTheft, Misconfiguration }
enum AccessControlServiceDefenseType{ Auth, TokenValidation, PolicyEnforcement, Revocation }

error ACS__NotOwner();
error ACS__Unauthorized();
error ACS__InvalidToken();
error ACS__Revoked();
error ACS__InsufficientRole();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE SERVICE (no checks, open access)
//    • Attack: Bypass
////////////////////////////////////////////////////////////////////////////////
contract AccessControlServiceVuln {
    event AccessRequested(
        address who,
        uint256 resourceId,
        AccessControlServiceType   ctype,
        bool                       granted,
        AccessControlServiceAttackType attack
    );

    /// ❌ blindly grant access to any resource
    function requestAccess(uint256 resourceId) external {
        emit AccessRequested(msg.sender, resourceId, AccessControlServiceType.Centralized, true,
                              AccessControlServiceAttackType.Bypass);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB (replay & token theft)
//    • Attack: Replay, TokenTheft
////////////////////////////////////////////////////////////////////////////////
contract Attack_AccessControlService {
    AccessControlServiceVuln public target;
    constructor(AccessControlServiceVuln _t) { target = _t; }

    /// replay a prior access request
    function replayRequest(uint256 resourceId) external {
        target.requestAccess(resourceId);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE ACL SERVICE (Centralized + Auth)
//    • Defense: Auth – only owner‐granted users may access
////////////////////////////////////////////////////////////////////////////////
contract AccessControlServiceSafeAuth {
    address public owner;
    mapping(uint256 => mapping(address => bool)) public acl;
    event AccessRequested(
        address who,
        uint256 resourceId,
        AccessControlServiceType   ctype,
        bool                       granted,
        AccessControlServiceDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// owner grants or revokes permission
    function setPermission(uint256 resourceId, address user, bool ok) external {
        if (msg.sender != owner) revert ACS__NotOwner();
        acl[resourceId][user] = ok;
    }

    /// ✅ only authorized users can access
    function requestAccess(uint256 resourceId) external {
        bool ok = acl[resourceId][msg.sender];
        if (!ok) revert ACS__Unauthorized();
        emit AccessRequested(msg.sender, resourceId, AccessControlServiceType.Centralized, true,
                              AccessControlServiceDefenseType.Auth);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE TOKEN SERVICE (TokenBased + TokenValidation + Revocation)
//    • Defense: TokenValidation, Revocation
////////////////////////////////////////////////////////////////////////////////
contract AccessControlServiceSafeToken {
    address public owner;
    mapping(bytes32 => uint256) public tokenToResource;
    mapping(bytes32 => bool)    public revoked;
    event AccessRequested(
        address who,
        uint256 resourceId,
        AccessControlServiceType   ctype,
        bool                       granted,
        AccessControlServiceDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }

    /// owner issues a token for a resource
    function issueToken(bytes32 token, uint256 resourceId) external {
        if (msg.sender != owner) revert ACS__NotOwner();
        tokenToResource[token] = resourceId;
    }

    /// owner may revoke a token
    function revokeToken(bytes32 token) external {
        if (msg.sender != owner) revert ACS__NotOwner();
        revoked[token] = true;
    }

    /// ✅ validate token and check revocation
    function requestAccessWithToken(bytes32 token) external {
        if (revoked[token]) revert ACS__Revoked();
        uint256 rid = tokenToResource[token];
        if (rid == 0) revert ACS__InvalidToken();
        emit AccessRequested(msg.sender, rid, AccessControlServiceType.TokenBased, true,
                              AccessControlServiceDefenseType.TokenValidation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE POLICY SERVICE (PolicyBased + RBAC)
//    • Defense: PolicyEnforcement – role‐based access control
////////////////////////////////////////////////////////////////////////////////
contract AccessControlServiceSafePolicy {
    mapping(address => bytes32[])    public rolesOf;
    mapping(bytes32 => uint256[])    public resourcesForRole;
    event AccessRequested(
        address who,
        uint256 resourceId,
        AccessControlServiceType   ctype,
        bool                       granted,
        AccessControlServiceDefenseType defense
    );

    error ACS__NoRole();

    /// assign a role to a user
    function assignRole(address user, bytes32 role) external {
        // in practice, restricted to an admin; omitted for brevity
        rolesOf[user].push(role);
    }

    /// map a role to permitted resources
    function setRoleResources(bytes32 role, uint256[] calldata resourceIds) external {
        // in practice, restricted to an admin
        resourcesForRole[role] = resourceIds;
    }

    /// ✅ enforce that caller has a role permitting the resource
    function requestAccess(uint256 resourceId) external {
        bytes32[] storage userRoles = rolesOf[msg.sender];
        for (uint i = 0; i < userRoles.length; i++) {
            bytes32 role = userRoles[i];
            uint256[] storage permitted = resourcesForRole[role];
            for (uint j = 0; j < permitted.length; j++) {
                if (permitted[j] == resourceId) {
                    emit AccessRequested(msg.sender, resourceId, AccessControlServiceType.PolicyBased, true,
                                          AccessControlServiceDefenseType.PolicyEnforcement);
                    return;
                }
            }
        }
        revert ACS__NoRole();
    }
}
