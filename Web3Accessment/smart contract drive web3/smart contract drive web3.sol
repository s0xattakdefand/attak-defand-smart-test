// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SmartContractDriveWeb3Suite.sol
/// @notice On‐chain analogues of “Smart Contract Driven Web3” patterns:
///   Types: TokenTransfer, DataStorage, Governance, OracleInteraction  
///   AttackTypes: Reentrancy, DataTampering, FrontRunning, OracleManipulation  
///   DefenseTypes: AccessControl, ReentrancyGuard, DataValidation, RateLimit, SignatureValidation

enum SCDW3Type             { TokenTransfer, DataStorage, Governance, OracleInteraction }
enum SCDW3AttackType       { Reentrancy, DataTampering, FrontRunning, OracleManipulation }
enum SCDW3DefenseType      { AccessControl, ReentrancyGuard, DataValidation, RateLimit, SignatureValidation }

error SCDW3__NotAuthorized();
error SCDW3__ReentrancyDetected();
error SCDW3__InvalidData();
error SCDW3__TooManyRequests();
error SCDW3__InvalidSignature();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE DRIVE CONTRACT
//    • ❌ no checks: anyone may transfer or store arbitrary data → Reentrancy, DataTampering
////////////////////////////////////////////////////////////////////////////////
contract SCDW3Vuln {
    mapping(address => uint256) public balances;
    mapping(bytes32 => string) public store;

    event TokenTransferred(
        address indexed who,
        address indexed to,
        uint256 amount,
        SCDW3Type dtype,
        SCDW3AttackType attack
    );
    event DataStored(
        address indexed who,
        bytes32 indexed key,
        string data,
        SCDW3Type dtype,
        SCDW3AttackType attack
    );

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok);
        emit TokenTransferred(msg.sender, to, amount, SCDW3Type.TokenTransfer, SCDW3AttackType.Reentrancy);
    }

    function storeData(bytes32 key, string calldata data) external {
        store[key] = data;
        emit DataStored(msg.sender, key, data, SCDW3Type.DataStorage, SCDW3AttackType.DataTampering);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates reentrancy, tampering, frontrunning, oracle manipulation
////////////////////////////////////////////////////////////////////////////////
contract Attack_SCDW3 {
    SCDW3Vuln public target;
    bytes32 public lastKey;
    string  public lastData;

    constructor(SCDW3Vuln _t) { target = _t; }

    receive() external payable {
        if (address(target).balance >= msg.value) {
            target.transfer(msg.sender, msg.value);
        }
    }

    function attackReentrancy() external payable {
        target.deposit{value: msg.value}();
        target.transfer(address(this), msg.value);
    }

    function tamperData(bytes32 key, string calldata fake) external {
        target.storeData(key, fake);
        lastKey = key;
        lastData = fake;
    }

    function replayData() external {
        target.storeData(lastKey, lastData);
    }

    function frontRun(bytes32 key, string calldata data) external {
        // simulate frontrunning another store
        target.storeData(key, data);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WITH ACCESS CONTROL
//    • ✅ Defense: AccessControl – only owner may transfer or store
////////////////////////////////////////////////////////////////////////////////
contract SCDW3SafeAccess {
    mapping(address => uint256) public balances;
    mapping(bytes32 => string) public store;
    address public owner;

    event TokenTransferred(
        address indexed who,
        address indexed to,
        uint256 amount,
        SCDW3Type dtype,
        SCDW3DefenseType defense
    );
    event DataStored(
        address indexed who,
        bytes32 indexed key,
        string data,
        SCDW3Type dtype,
        SCDW3DefenseType defense
    );

    constructor() { owner = msg.sender; }
    modifier onlyOwner() {
        if (msg.sender != owner) revert SCDW3__NotAuthorized();
        _;
    }

    function deposit() external payable {
        require(msg.sender == owner);
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) external onlyOwner {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok);
        emit TokenTransferred(msg.sender, to, amount, SCDW3Type.TokenTransfer, SCDW3DefenseType.AccessControl);
    }

    function storeData(bytes32 key, string calldata data) external onlyOwner {
        store[key] = data;
        emit DataStored(msg.sender, key, data, SCDW3Type.DataStorage, SCDW3DefenseType.AccessControl);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WITH REENTRANCY GUARD & RATE LIMIT
//    • ✅ Defense: ReentrancyGuard – prevent nested calls
//               RateLimit        – cap stores per block
////////////////////////////////////////////////////////////////////////////////
contract SCDW3SafeValidate {
    mapping(address => uint256) public balances;
    mapping(bytes32 => string) public store;
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public storesInBlock;
    uint256 public constant MAX_STORES = 3;
    bool private _entered;

    event TokenTransferred(
        address indexed who,
        address indexed to,
        uint256 amount,
        SCDW3Type dtype,
        SCDW3DefenseType defense
    );
    event DataStored(
        address indexed who,
        bytes32 indexed key,
        string data,
        SCDW3Type dtype,
        SCDW3DefenseType defense
    );

    modifier noReentry() {
        if (_entered) revert SCDW3__ReentrancyDetected();
        _entered = true;
        _;
        _entered = false;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function transfer(address to, uint256 amount) external noReentry {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok);
        emit TokenTransferred(msg.sender, to, amount, SCDW3Type.TokenTransfer, SCDW3DefenseType.ReentrancyGuard);
    }

    function storeData(bytes32 key, string calldata data) external {
        if (bytes(data).length == 0) revert SCDW3__InvalidData();
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender] = block.number;
            storesInBlock[msg.sender] = 0;
        }
        storesInBlock[msg.sender]++;
        if (storesInBlock[msg.sender] > MAX_STORES) revert SCDW3__TooManyRequests();

        store[key] = data;
        emit DataStored(msg.sender, key, data, SCDW3Type.DataStorage, SCDW3DefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE ADVANCED WITH SIGNATURE VALIDATION & ORACLE GUARD
//    • ✅ Defense: SignatureValidation – off‐chain signed operations
//               OracleValidation   – stub for secure oracle calls
////////////////////////////////////////////////////////////////////////////////
contract SCDW3SafeAdvanced {
    mapping(address => uint256) public balances;
    mapping(bytes32 => string) public store;
    address public signer;

    event TokenTransferred(
        address indexed who,
        address indexed to,
        uint256 amount,
        SCDW3Type dtype,
        SCDW3DefenseType defense
    );
    event DataStored(
        address indexed who,
        bytes32 indexed key,
        string data,
        SCDW3Type dtype,
        SCDW3DefenseType defense
    );

    error SCDW3__InvalidSignature();

    constructor(address _signer) {
        signer = _signer;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function transfer(
        address to,
        uint256 amount,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||to||amount)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, to, amount));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SCDW3__InvalidSignature();

        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok,) = to.call{value: amount}("");
        require(ok);
        emit TokenTransferred(msg.sender, to, amount, SCDW3Type.TokenTransfer, SCDW3DefenseType.SignatureValidation);
    }

    function storeData(
        bytes32 key,
        string calldata data,
        bytes calldata sig
    ) external {
        // verify signature over (msg.sender||key||data)
        bytes32 h = keccak256(abi.encodePacked(msg.sender, key, data));
        bytes32 eth = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig,(uint8,bytes32,bytes32));
        if (ecrecover(eth, v, r, s) != signer) revert SCDW3__InvalidSignature();

        store[key] = data;
        emit DataStored(msg.sender, key, data, SCDW3Type.DataStorage, SCDW3DefenseType.SignatureValidation);
    }
}
