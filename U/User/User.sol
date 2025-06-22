// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title UserSuite.sol
/// @notice Four “User” patterns illustrating common pitfalls in user management
///         and hardened defenses.

enum UserType           { Admin, Member, Guest }
enum UserAttackType     { PrivilegeEscalation, ProfileHijack, FloodRegistration, OverrideAttempt }
enum UserDefenseType    { OwnerOnly, SelfOnly, RateLimit, ImmutableOnce }

error U__NotOwner();
error U__NotSelf();
error U__TooMany();
error U__AlreadySet();

////////////////////////////////////////////////////////////////////////////////
// 1) UNRESTRICTED ROLE ASSIGNMENT
//
//   • Vulnerable: anyone may change any user’s role
//   • Attack: grant self Admin privileges
//   • Defense: only owner may assign roles
////////////////////////////////////////////////////////////////////////////////
contract UserRoleVuln {
    mapping(address => UserType) public roles;
    event RoleChanged(address indexed who, UserType newRole, UserAttackType attack);

    function setRole(address user, UserType role) external {
        roles[user] = role;
        emit RoleChanged(user, role, UserAttackType.PrivilegeEscalation);
    }
}

contract Attack_UserRole {
    UserRoleVuln public target;
    constructor(UserRoleVuln _t) { target = _t; }
    function elevate() external {
        // attacker makes self Admin
        target.setRole(msg.sender, UserType.Admin);
    }
}

contract UserRoleSafe {
    mapping(address => UserType) public roles;
    address public owner;
    event RoleChanged(address indexed who, UserType newRole, UserDefenseType defense);

    constructor() { owner = msg.sender; }

    function setRole(address user, UserType role) external {
        if (msg.sender != owner) revert U__NotOwner();
        roles[user] = role;
        emit RoleChanged(user, role, UserDefenseType.OwnerOnly);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) PROFILE HIJACK
//
//   • Vulnerable: anyone may update any user’s profile
//   • Attack: overwrite another’s profile
//   • Defense: only the user themselves may update their profile
////////////////////////////////////////////////////////////////////////////////
contract UserProfileVuln {
    mapping(address => string) public profile;
    event ProfileUpdated(address indexed user, string data, UserAttackType attack);

    function setProfile(address user, string calldata data) external {
        profile[user] = data;
        emit ProfileUpdated(user, data, UserAttackType.ProfileHijack);
    }
}

contract Attack_UserProfile {
    UserProfileVuln public target;
    constructor(UserProfileVuln _t) { target = _t; }
    function hijack(address victim, string calldata fake) external {
        target.setProfile(victim, fake);
    }
}

contract UserProfileSafe {
    mapping(address => string) public profile;
    event ProfileUpdated(address indexed user, string data, UserDefenseType defense);

    function setProfile(string calldata data) external {
        // only self may update
        profile[msg.sender] = data;
        emit ProfileUpdated(msg.sender, data, UserDefenseType.SelfOnly);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) REGISTRATION FLOOD (DoS)
//
//   • Vulnerable: unlimited registrations per user per block
//   • Attack: flood register() to exhaust storage/events
//   • Defense: rate‑limit registrations per block
////////////////////////////////////////////////////////////////////////////////
contract UserRegistrationVuln {
    address[] public users;
    event Registered(address indexed user, UserAttackType attack);

    function register() external {
        users.push(msg.sender);
        emit Registered(msg.sender, UserAttackType.FloodRegistration);
    }
}

contract Attack_UserRegistration {
    UserRegistrationVuln public target;
    constructor(UserRegistrationVuln _t) { target = _t; }
    function flood(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            target.register();
        }
    }
}

contract UserRegistrationSafe {
    address[] public users;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;
    event Registered(address indexed user, UserDefenseType defense);

    function register() external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert U__TooMany();

        users.push(msg.sender);
        emit Registered(msg.sender, UserDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) IMMUTABLE PROFILE (ONE‑TIME SET)
//
//   • Vulnerable: profiles may be overwritten indefinitely
//   • Attack: attempt to override profile
//   • Defense: allow setting profile only once
////////////////////////////////////////////////////////////////////////////////
contract UserProfileImmutableVuln {
    mapping(address => string) public profile;

    function setProfile(string calldata data) external {
        profile[msg.sender] = data;
    }
}

contract Attack_UserProfileImmutable {
    UserProfileImmutableVuln public target;
    constructor(UserProfileImmutableVuln _t) { target = _t; }
    function override(string calldata newData) external {
        target.setProfile(newData);
    }
}

contract UserProfileImmutableSafe {
    mapping(address => string) public profile;
    mapping(address => bool)  private _set;
    event ProfileSet(address indexed user, string data, UserDefenseType defense);

    function setProfile(string calldata data) external {
        if (_set[msg.sender]) revert U__AlreadySet();
        _set[msg.sender] = true;
        profile[msg.sender] = data;
        emit ProfileSet(msg.sender, data, UserDefenseType.ImmutableOnce);
    }
}
