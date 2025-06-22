// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WarningBannerSuite.sol
/// @notice On‐chain analogues of “Warning Banner” display patterns:
///   Types: LoginBanner, WebBanner, MobileBanner, APIBanner  
///   AttackTypes: Bypass, Tampering, Spoofing, Skipping  
///   DefenseTypes: ImmutableStorage, UserConfirmation, AuditLogging, RateLimit  

enum WarningBannerType         { LoginBanner, WebBanner, MobileBanner, APIBanner }
enum WarningBannerAttackType   { Bypass, Tampering, Spoofing, Skipping }
enum WarningBannerDefenseType  { ImmutableStorage, UserConfirmation, AuditLogging, RateLimit }

error WB__NotAuthorized();
error WB__AlreadyAcknowledged();
error WB__TooManyDisplays();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE BANNER
//    • ❌ no enforcement: users may skip or spoof banner → Bypass, Skipping
////////////////////////////////////////////////////////////////////////////////
contract WarningBannerVuln {
    mapping(WarningBannerType => string) public message;
    event BannerShown(
        address indexed who,
        WarningBannerType  btype,
        string             msg,
        WarningBannerAttackType attack
    );

    function setBanner(WarningBannerType btype, string calldata msg_) external {
        message[btype] = msg_;
    }

    function showBanner(WarningBannerType btype) external {
        // no enforcement: user may ignore or spoof
        emit BannerShown(msg.sender, btype, message[btype], WarningBannerAttackType.Bypass);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates spoofed display and skipping
////////////////////////////////////////////////////////////////////////////////
contract Attack_WarningBanner {
    WarningBannerVuln public target;

    constructor(WarningBannerVuln _t) {
        target = _t;
    }

    function spoofDisplay(WarningBannerType btype) external {
        // attacker pretends to show banner without real display
        target.showBanner(btype);
    }

    function skipBanner(WarningBannerType btype) external {
        // attacker simply does not call showBanner
        // stub: emit event via vulnerable contract
        target.showBanner(btype);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH IMMUTABLE STORAGE
//    • ✅ Defense: ImmutableStorage – banner cannot be changed once set
////////////////////////////////////////////////////////////////////////////////
contract WarningBannerSafeImmutable {
    mapping(WarningBannerType => string) public message;
    mapping(WarningBannerType => bool) private initialized;
    event BannerShown(
        address indexed who,
        WarningBannerType  btype,
        string             msg,
        WarningBannerDefenseType defense
    );

    error WB__NotAuthorized();

    function setBanner(WarningBannerType btype, string calldata msg_) external {
        // only allow initial set
        if (initialized[btype]) revert WB__NotAuthorized();
        message[btype] = msg_;
        initialized[btype] = true;
    }

    function showBanner(WarningBannerType btype) external {
        emit BannerShown(msg.sender, btype, message[btype], WarningBannerDefenseType.ImmutableStorage);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH USER CONFIRMATION
//    • ✅ Defense: UserConfirmation – require explicit ack before proceeding
////////////////////////////////////////////////////////////////////////////////
contract WarningBannerSafeConfirmation {
    mapping(WarningBannerType => string) public message;
    mapping(address => mapping(WarningBannerType => bool)) public acknowledged;
    event BannerShown(
        address indexed who,
        WarningBannerType  btype,
        string             msg,
        WarningBannerDefenseType defense
    );
    event BannerAcknowledged(
        address indexed who,
        WarningBannerType  btype,
        WarningBannerDefenseType defense
    );

    error WB__AlreadyAcknowledged();

    function setBanner(WarningBannerType btype, string calldata msg_) external {
        message[btype] = msg_;
    }

    function showBanner(WarningBannerType btype) external {
        emit BannerShown(msg.sender, btype, message[btype], WarningBannerDefenseType.UserConfirmation);
    }

    function acknowledge(WarningBannerType btype) external {
        if (acknowledged[msg.sender][btype]) revert WB__AlreadyAcknowledged();
        acknowledged[msg.sender][btype] = true;
        emit BannerAcknowledged(msg.sender, btype, WarningBannerDefenseType.UserConfirmation);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH AUDIT LOGGING & RATE LIMIT
//    • ✅ Defense: AuditLogging – record every display  
//               RateLimit – cap shows per block per user
////////////////////////////////////////////////////////////////////////////////
contract WarningBannerSafeAdvanced {
    mapping(WarningBannerType => string) public message;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public showsInBlock;
    uint256 public constant MAX_SHOWS = 5;

    event BannerShown(
        address indexed who,
        WarningBannerType  btype,
        string             msg,
        WarningBannerDefenseType defense
    );
    event AuditLog(
        address indexed who,
        WarningBannerType  btype,
        WarningBannerDefenseType defense
    );

    error WB__TooManyDisplays();

    function setBanner(WarningBannerType btype, string calldata msg_) external {
        message[btype] = msg_;
    }

    function showBanner(WarningBannerType btype) external {
        // rate-limit per user per block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            showsInBlock[msg.sender] = 0;
        }
        showsInBlock[msg.sender]++;
        if (showsInBlock[msg.sender] > MAX_SHOWS) revert WB__TooManyDisplays();

        // audit log
        emit AuditLog(msg.sender, btype, WarningBannerDefenseType.AuditLogging);
        // main display event
        emit BannerShown(msg.sender, btype, message[btype], WarningBannerDefenseType.RateLimit);
    }
}
