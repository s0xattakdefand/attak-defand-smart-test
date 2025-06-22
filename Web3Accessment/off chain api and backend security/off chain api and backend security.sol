// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title OffChainAPIAndBackendSecuritySuite.sol
/// @notice On‐chain analogues of “Off-Chain API and Backend Security” patterns:
///   Types: RateLimit, Authenticated, SignedRequest, PrivateNetwork  
///   AttackTypes: UnauthorizedAccess, Injection, Replay, DenialOfService  
///   DefenseTypes: AccessControl, InputValidation, RateLimit, SignatureValidation, AuditLogging

enum OffChainType             { RateLimit, Authenticated, SignedRequest, PrivateNetwork }
enum OffChainAttackType       { UnauthorizedAccess, Injection, Replay, DenialOfService }
enum OffChainDefenseType      { AccessControl, InputValidation, RateLimit, SignatureValidation, AuditLogging }

error OCB__NotAuthorized();
error OCB__InvalidInput();
error OCB__TooManyRequests();
error OCB__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE OFF-CHAIN API PROXY
//    • ❌ no checks: anyone may register or call endpoints → UnauthorizedAccess
////////////////////////////////////////////////////////////////////////////////
contract OffChainApiVuln {
    mapping(string => string) public backendData;
    event EndpointRegistered(
        address indexed who,
        string           endpoint,
        OffChainType     otype,
        OffChainAttackType attack
    );
    event EndpointCalled(
        address indexed who,
        string           endpoint,
        string           response,
        OffChainType     otype,
        OffChainAttackType attack
    );

    function registerEndpoint(string calldata endpoint, string calldata response, OffChainType otype) external {
        backendData[endpoint] = response;
        emit EndpointRegistered(msg.sender, endpoint, otype, OffChainAttackType.UnauthorizedAccess);
    }

    function callEndpoint(string calldata endpoint, OffChainType otype) external view returns (string memory) {
        string memory resp = backendData[endpoint];
        emit EndpointCalled(msg.sender, endpoint, resp, otype, OffChainAttackType.UnauthorizedAccess);
        return resp;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates injection, replay, DOS
////////////////////////////////////////////////////////////////////////////////
contract Attack_OffChainApi {
    OffChainApiVuln public target;
    string public lastEndpoint;
    string public lastResponse;

    constructor(OffChainApiVuln _t) {
        target = _t;
    }

    function injectData(string calldata endpoint, string calldata fake) external {
        target.registerEndpoint(endpoint, fake, OffChainType.Authenticated);
        lastEndpoint = endpoint;
        lastResponse = fake;
    }

    function replayCall() external {
        target.callEndpoint(lastEndpoint, OffChainType.RateLimit);
    }

    function floodEndpoint(string calldata endpoint, uint256 n) external {
        for (uint i = 0; i < n; i++) {
            target.callEndpoint(endpoint, OffChainType.RateLimit);
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may register or call
////////////////////////////////////////////////////////////////////////////////
contract OffChainApiSafeAccess {
    mapping(string => string) public backendData;
    address public owner;

    event EndpointRegistered(
        address indexed who,
        string           endpoint,
        OffChainType     otype,
        OffChainDefenseType defense
    );
    event EndpointCalled(
        address indexed who,
        string           endpoint,
        string           response,
        OffChainType     otype,
        OffChainDefenseType defense
    );

    constructor() {
        owner = msg.sender;
    }
    modifier onlyOwner() {
        if (msg.sender != owner) revert OCB__NotAuthorized();
        _;
    }

    function registerEndpoint(string calldata endpoint, string calldata response, OffChainType otype) external onlyOwner {
        backendData[endpoint] = response;
        emit EndpointRegistered(msg.sender, endpoint, otype, OffChainDefenseType.AccessControl);
    }

    function callEndpoint(string calldata endpoint, OffChainType otype) external view onlyOwner returns (string memory) {
        string memory resp = backendData[endpoint];
        emit EndpointCalled(msg.sender, endpoint, resp, otype, OffChainDefenseType.AccessControl);
        return resp;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH INPUT VALIDATION & RATE LIMIT
//    • ✅ Defense: InputValidation – nonempty endpoint  
//               RateLimit       – cap calls per block
////////////////////////////////////////////////////////////////////////////////
contract OffChainApiSafeValidate {
    mapping(string => string) public backendData;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;

    event EndpointRegistered(
        address indexed who,
        string           endpoint,
        OffChainType     otype,
        OffChainDefenseType defense
    );
    event EndpointCalled(
        address indexed who,
        string           endpoint,
        string           response,
        OffChainType     otype,
        OffChainDefenseType defense
    );

    function registerEndpoint(string calldata endpoint, string calldata response, OffChainType otype) external {
        if (bytes(endpoint).length == 0 || bytes(response).length == 0) revert OCB__InvalidInput();
        backendData[endpoint] = response;
        emit EndpointRegistered(msg.sender, endpoint, otype, OffChainDefenseType.InputValidation);
    }

    function callEndpoint(string calldata endpoint, OffChainType otype) external returns (string memory) {
        if (bytes(endpoint).length == 0) revert OCB__InvalidInput();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) revert OCB__TooManyRequests();

        string memory resp = backendData[endpoint];
        emit EndpointCalled(msg.sender, endpoint, resp, otype, OffChainDefenseType.RateLimit);
        return resp;
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & AUDIT LOGGING
//    • ✅ Defense: SignatureValidation – require admin‐signed params  
//               AuditLogging      – record each operation
////////////////////////////////////////////////////////////////////////////////
contract OffChainApiSafeAdvanced {
    mapping(string => string) public backendData;
    address public signer;

    event EndpointRegistered(
        address indexed who,
        string           endpoint,
        OffChainType     otype,
        OffChainDefenseType defense
    );
    event EndpointCalled(
        address indexed who,
        string           endpoint,
        string           response,
        OffChainType     otype,
        OffChainDefenseType defense
    );
    event AuditLog(
        address indexed who,
        string           action,
        string           endpoint,
        OffChainDefenseType defense
    );

    error OCB__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function registerEndpoint(
        string calldata endpoint,
        string calldata response,
        OffChainType otype,
        bytes calldata sig
    ) external {
        bytes32 h = keccak256(abi.encodePacked("REGISTER", endpoint, response, otype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert OCB__InvalidSignature();

        backendData[endpoint] = response;
        emit EndpointRegistered(msg.sender, endpoint, otype, OffChainDefenseType.SignatureValidation);
        emit AuditLog(msg.sender, "registerEndpoint", endpoint, OffChainDefenseType.AuditLogging);
    }

    function callEndpoint(
        string calldata endpoint,
        OffChainType otype,
        bytes calldata sig
    ) external returns (string memory) {
        bytes32 h = keccak256(abi.encodePacked("CALL", endpoint, otype));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert OCB__InvalidSignature();

        string memory resp = backendData[endpoint];
        emit EndpointCalled(msg.sender, endpoint, resp, otype, OffChainDefenseType.AuditLogging);
        emit AuditLog(msg.sender, "callEndpoint", endpoint, OffChainDefenseType.AuditLogging);
        return resp;
    }
}
