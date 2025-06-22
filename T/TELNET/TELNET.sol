// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title TelnetSuite.sol
/// @notice On‑chain analogues of common “Telnet” patterns:
///   Types: PlainAuth, CommandExec, LoginFlood, BannerEcho  
///   AttackTypes: SniffCreds, InjectCommand, FloodLogin, SpoofBanner  
///   DefenseTypes: EncryptedAuth, CmdWhitelist, RateLimit, HashLogging  

enum TelnetType         { PlainAuth, CommandExec, LoginFlood, BannerEcho }
enum TelnetAttackType   { SniffCreds, InjectCommand, FloodLogin, SpoofBanner }
enum TelnetDefenseType  { EncryptedAuth, CmdWhitelist, RateLimit, HashLogging }

error TN__BadCredentials();
error TN__CmdNotAllowed();
error TN__TooManyAttempts();
error TN__NotOwner();

////////////////////////////////////////////////////////////////////////
// 1) PLAINTEXT AUTH (VULNERABLE)
//    • Type: PlainAuth
//    • Attack: SniffCreds (credentials logged in clear)
//    • Defense: EncryptedAuth (store/compare only hashes)
////////////////////////////////////////////////////////////////////////
contract TelnetVulnAuth {
    mapping(address => bool) public loggedIn;
    event Login(address indexed who, string user, string pass, TelnetAttackType attack);

    function login(string calldata user, string calldata pass) external {
        // ❌ logs credentials in clear
        emit Login(msg.sender, user, pass, TelnetAttackType.SniffCreds);
        loggedIn[msg.sender] = true;
    }
}

contract Attack_TelnetCreds {
    TelnetVulnAuth public target;
    constructor(TelnetVulnAuth _t) { target = _t; }
    function sniff(string calldata u, string calldata p) external {
        // attacker simply calls login to emit clear credentials
        target.login(u, p);
    }
}

contract TelnetSafeAuth {
    mapping(address => bytes32) private _pwHash;
    mapping(address => bool)    public loggedIn;
    address public owner;
    event Login(address indexed who, TelnetDefenseType defense);

    constructor() { owner = msg.sender; }

    /// owner must set user→hash(password)
    function setUser(address user, bytes32 pwHash) external {
        if (msg.sender != owner) revert TN__NotOwner();
        _pwHash[user] = pwHash;
    }

    function login(string calldata user, string calldata pass) external {
        // ✅ compare only hashes, no clear logging
        bytes32 h = keccak256(abi.encodePacked(user, ":", pass));
        if (h != _pwHash[msg.sender]) revert TN__BadCredentials();
        loggedIn[msg.sender] = true;
        emit Login(msg.sender, TelnetDefenseType.EncryptedAuth);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) COMMAND EXECUTION (VULNERABLE)
//    • Type: CommandExec
//    • Attack: InjectCommand (no sanitization)
//    • Defense: CmdWhitelist (only allowed commands)
////////////////////////////////////////////////////////////////////////
contract TelnetVulnCmd {
    mapping(address => bool) public loggedIn;
    event Exec(address indexed who, string cmd, TelnetAttackType attack);

    function login(string calldata /*unused*/, string calldata /*unused*/) external {
        loggedIn[msg.sender] = true;
    }

    function exec(string calldata cmd) external {
        require(loggedIn[msg.sender], "not logged in");
        // ❌ no sanitization → attack can inject arbitrary payload
        emit Exec(msg.sender, cmd, TelnetAttackType.InjectCommand);
    }
}

contract TelnetSafeCmd {
    mapping(address => bool) public loggedIn;
    mapping(string => bool) public allowedCmd;
    address public owner;
    event Exec(address indexed who, string cmd, TelnetDefenseType defense);

    constructor() { owner = msg.sender; }

    function setAllowed(string calldata cmd, bool ok) external {
        if (msg.sender != owner) revert TN__NotOwner();
        allowedCmd[cmd] = ok;
    }

    function login() external {
        loggedIn[msg.sender] = true;
    }

    function exec(string calldata cmd) external {
        require(loggedIn[msg.sender], "not logged in");
        // ✅ only allow whitelisted commands
        if (!allowedCmd[cmd]) revert TN__CmdNotAllowed();
        emit Exec(msg.sender, cmd, TelnetDefenseType.CmdWhitelist);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) LOGIN FLOOD (VULNERABLE)
//    • Type: LoginFlood
//    • Attack: FloodLogin (unlimited attempts)
//    • Defense: RateLimit (cap attempts per block)
////////////////////////////////////////////////////////////////////////
contract TelnetVulnFlood {
    mapping(address => uint256) public attempts;
    event Login(address indexed who, TelnetAttackType attack);

    function login(string calldata /*u*/, string calldata /*p*/) external {
        // ❌ no rate‑limit
        attempts[msg.sender]++;
        emit Login(msg.sender, TelnetAttackType.FloodLogin);
    }
}

contract Attack_TelnetFlood {
    TelnetVulnFlood public target;
    constructor(TelnetVulnFlood _t) { target = _t; }
    function flood(uint n) external {
        for (uint i = 0; i < n; i++) {
            target.login("", "");
        }
    }
}

contract TelnetSafeFlood {
    mapping(address => uint256) public attempts;
    mapping(address => uint256) public lastBlock;
    uint256 public constant MAX_PER_BLOCK = 3;
    event Login(address indexed who, TelnetDefenseType defense);

    function login(string calldata /*u*/, string calldata /*p*/) external {
        // reset counter each block
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            attempts[msg.sender] = 0;
        }
        attempts[msg.sender]++;
        if (attempts[msg.sender] > MAX_PER_BLOCK) revert TN__TooManyAttempts();
        emit Login(msg.sender, TelnetDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) BANNER ECHO (VULNERABLE)
//    • Type: BannerEcho
//    • Attack: SpoofBanner (logs raw banner including user data)
//    • Defense: HashLogging (emit only hash of banner)
////////////////////////////////////////////////////////////////////////
contract TelnetVulnBanner {
    event Banner(address indexed who, string banner, TelnetAttackType attack);

    function banner(string calldata text) external {
        // ❌ logs raw banner text
        emit Banner(msg.sender, text, TelnetAttackType.SpoofBanner);
    }
}

contract TelnetSafeBanner {
    event Banner(address indexed who, bytes32 bannerHash, TelnetDefenseType defense);

    function banner(string calldata text) external {
        // ✅ emit only hash to avoid leaking
        emit Banner(msg.sender, keccak256(bytes(text)), TelnetDefenseType.HashLogging);
    }
}
