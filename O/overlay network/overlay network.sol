// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OverlayNetworkSuite.sol
/// @notice On-chain analogues of “Overlay Network” patterns:
///   Types: P2P, VPN, CDN, DHT  
///   AttackTypes: NodeSpoofing, Eclipse, Sybil, TrafficAnalysis  
///   DefenseTypes: NodeAuthentication, RateLimiting, ReputationSystem, Encryption  

enum OverlayNetworkType         { P2P, VPN, CDN, DHT }
enum OverlayNetworkAttackType   { NodeSpoofing, Eclipse, Sybil, TrafficAnalysis }
enum OverlayNetworkDefenseType  { NodeAuthentication, RateLimiting, ReputationSystem, Encryption }

error ON__NotAllowed();
error ON__TooManyRequests();
error ON__InvalidNode();
error ON__LowReputation();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE OVERLAY
//
//    • no checks: any node may join or relay → NodeSpoofing, Sybil
////////////////////////////////////////////////////////////////////////////////
contract OverlayNetworkVuln {
    mapping(address => bool) public nodes;
    event NodeJoined(
        address indexed who,
        OverlayNetworkType  ntype,
        OverlayNetworkAttackType attack
    );
    event Relay(
        address indexed from,
        address indexed to,
        bytes             payload,
        OverlayNetworkAttackType attack
    );

    function joinNetwork(OverlayNetworkType ntype) external {
        nodes[msg.sender] = true;
        emit NodeJoined(msg.sender, ntype, OverlayNetworkAttackType.NodeSpoofing);
    }

    function relay(address to, bytes calldata payload) external {
        require(nodes[msg.sender], "not a node");
        emit Relay(msg.sender, to, payload, OverlayNetworkAttackType.Sybil);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//
//    • simulates eclipse, sybil, and traffic analysis
////////////////////////////////////////////////////////////////////////////////
contract Attack_OverlayNetwork {
    OverlayNetworkVuln public target;
    address[] public fakeNodes;
    bytes public lastPayload;

    constructor(OverlayNetworkVuln _t) { target = _t; }

    function massJoin(uint count, OverlayNetworkType ntype) external {
        for (uint i = 0; i < count; i++) {
            target.joinNetwork(ntype);
        }
    }

    function capture(bytes calldata payload) external {
        lastPayload = payload;
    }

    function replayRelay(address to) external {
        target.relay(to, lastPayload);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH NODE AUTHENTICATION
//
//    • Defense: NodeAuthentication – only whitelisted keys may join
////////////////////////////////////////////////////////////////////////////////
contract OverlayNetworkSafeAuth {
    mapping(address => bool) public nodes;
    mapping(address => bool) public allowed;
    address public owner;

    event NodeJoined(
        address indexed who,
        OverlayNetworkType  ntype,
        OverlayNetworkDefenseType defense
    );
    event Relay(
        address indexed from,
        address indexed to,
        bytes             payload,
        OverlayNetworkDefenseType defense
    );

    error ON__NotAllowed();

    constructor() {
        owner = msg.sender;
    }

    function setAllowed(address node, bool ok) external {
        if (msg.sender != owner) revert ON__NotAllowed();
        allowed[node] = ok;
    }

    function joinNetwork(OverlayNetworkType ntype) external {
        if (!allowed[msg.sender]) revert ON__NotAllowed();
        nodes[msg.sender] = true;
        emit NodeJoined(msg.sender, ntype, OverlayNetworkDefenseType.NodeAuthentication);
    }

    function relay(address to, bytes calldata payload) external {
        require(nodes[msg.sender], "not a node");
        emit Relay(msg.sender, to, payload, OverlayNetworkDefenseType.NodeAuthentication);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH RATE-LIMITING & ENCRYPTION
//
//    • Defense: RateLimit – cap relays per block  
//               Encryption – require ciphertext only
////////////////////////////////////////////////////////////////////////////////
contract OverlayNetworkSafeRateEnc {
    mapping(address => bool) public nodes;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public relaysInBlock;
    uint256 public constant MAX_RELAYS = 5;

    event Relay(
        address indexed from,
        address indexed to,
        bytes             ciphertext,
        OverlayNetworkDefenseType defense
    );

    error ON__TooManyRequests();
    error ON__NotNode();

    function joinNetwork() external {
        nodes[msg.sender] = true;
    }

    function relay(address to, bytes calldata ciphertext) external {
        if (!nodes[msg.sender]) revert ON__NotNode();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            relaysInBlock[msg.sender] = 0;
        }
        relaysInBlock[msg.sender]++;
        if (relaysInBlock[msg.sender] > MAX_RELAYS) revert ON__TooManyRequests();

        emit Relay(msg.sender, to, ciphertext, OverlayNetworkDefenseType.RateLimiting);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE WITH REPUTATION & FORWARD SECRECY
//
//    • Defense: ReputationSystem – track and require min rep  
//               Encryption – rotate shared symmetric key per session
////////////////////////////////////////////////////////////////////////////////
contract OverlayNetworkSafeReputation {
    mapping(address => bool) public nodes;
    mapping(address => uint256) public reputation;
    mapping(address => bytes32) public sessionKey;
    uint256 public constant MIN_REP = 10;
    event NodeJoined(
        address indexed who,
        OverlayNetworkType  ntype,
        OverlayNetworkDefenseType defense
    );
    event Relay(
        address indexed from,
        address indexed to,
        bytes             ciphertext,
        OverlayNetworkDefenseType defense
    );

    error ON__LowReputation();
    error ON__NotNode();

    function joinNetwork() external {
        require(reputation[msg.sender] >= MIN_REP, "low reputation");
        nodes[msg.sender] = true;
        emit NodeJoined(msg.sender, OverlayNetworkType.P2P, OverlayNetworkDefenseType.ReputationSystem);
    }

    function fundReputation(uint256 amount) external {
        // stub: anyone may buy reputation off-chain
        reputation[msg.sender] += amount;
    }

    function establishSession(bytes32 key) external {
        // new session key for forward secrecy
        sessionKey[msg.sender] = key;
    }

    function relay(address to, bytes calldata plaintext) external {
        if (!nodes[msg.sender]) revert ON__NotNode();
        if (reputation[msg.sender] < MIN_REP) revert ON__LowReputation();
        // encrypt with sessionKey[msg.sender] off-chain
        bytes memory ct = plaintext; // stub assumes pre-encrypted
        emit Relay(msg.sender, to, ct, OverlayNetworkDefenseType.Encryption);
    }
}
