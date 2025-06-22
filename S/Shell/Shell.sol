// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// Shared errors
error Shell__NotOwner();
error Shell__SelectorNotAllowed();
error Loader__NotApproved();
error Loader__NotOwner();

////////////////////////////////////////////////////////////////////////////////
// 1) PUBLIC COMMAND SHELL
//    Anyone can execute arbitrary payload via call()
////////////////////////////////////////////////////////////////////////////////
contract PublicShellVuln {
    event Exec(address indexed who, bytes payload);

    /// ❌ No access control
    function exec(bytes calldata payload) external {
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Exec(msg.sender, payload);
    }
}

/// Attack: steal funds or self‑destruct the contract
contract Attack_PublicShell {
    PublicShellVuln public target;
    constructor(PublicShellVuln _t) { target = _t; }

    function hack() external {
        // e.g. self‑destruct via exec
        bytes memory p = abi.encodeWithSignature("selfdestruct(address)", msg.sender);
        target.exec(p);
    }
}

contract PublicShellSafe {
    address public immutable owner;
    event Exec(address indexed who, bytes payload);

    constructor() { owner = msg.sender; }

    /// ✅ Only owner may exec
    function exec(bytes calldata payload) external {
        if (msg.sender != owner) revert Shell__NotOwner();
        (bool ok, ) = address(this).call(payload);
        require(ok, "exec failed");
        emit Exec(msg.sender, payload);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) WEB SHELL (FALLBACK DELEGATECALL)
//    Fallback allows arbitrary delegatecall
////////////////////////////////////////////////////////////////////////////////
contract WebShellVuln {
    /// ❌ No selector check – full delegate‑call to self
    fallback() external payable {
        (bool ok, ) = address(this).delegatecall(msg.data);
        require(ok, "delegatecall failed");
    }
}

/// Attack: invoke arbitrary function via fallback
contract Attack_WebShell {
    WebShellVuln public target;
    constructor(WebShellVuln _t) { target = _t; }

    function exploit(bytes4 sel, bytes calldata args) external {
        // craft call data: selector + args
        bytes memory data = abi.encodePacked(sel, args);
        (bool ok, ) = address(target).call(data);
        require(ok);
    }
}

contract WebShellSafe {
    address public immutable owner;
    mapping(bytes4 => bool) public allowed;

    constructor(bytes4[] memory sels) {
        owner = msg.sender;
        for (uint i; i < sels.length; i++) {
            allowed[sels[i]] = true;
        }
    }

    /// Owner may add new allowed selectors
    function allow(bytes4 sel) external {
        if (msg.sender != owner) revert Shell__NotOwner();
        allowed[sel] = true;
    }

    fallback() external payable {
        bytes4 sel = msg.sig;
        if (!allowed[sel]) revert Shell__SelectorNotAllowed();
        (bool ok, ) = address(this).delegatecall(msg.data);
        require(ok, "delegatecall failed");
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) REVERSE SHELL (CALLBACK TO ATTACKER)
//    Contract sends data back via call()
////////////////////////////////////////////////////////////////////////////////
contract ReverseShellVuln {
    uint256 private secret = 0xDEADBEEF;
    event Sent(address indexed to, uint256 val);

    /// ❌ Anyone can trigger callback
    function trigger() external {
        (bool ok, ) = msg.sender.call(
            abi.encodeWithSignature("receiveSecret(uint256)", secret)
        );
        require(ok, "callback failed");
        emit Sent(msg.sender, secret);
    }
}

/// Attack collects the secret
contract Attack_ReverseShell {
    ReverseShellVuln public target;
    uint256 public got;
    bool    public ok;

    constructor(ReverseShellVuln _t) { target = _t; }

    function attack() external {
        target.trigger();
    }

    /// Called back by target.trigger()
    function receiveSecret(uint256 s) external {
        ok  = true;
        got = s;
    }
}

contract ReverseShellSafe {
    address public immutable owner;
    uint256 private secret = 0xC0FFEE;

    event Sent(address indexed to, uint256 val);

    constructor() { owner = msg.sender; }

    /// ✅ Only owner may trigger reverse‑shell
    function trigger() external {
        if (msg.sender != owner) revert Shell__NotOwner();
        (bool ok2, ) = msg.sender.call(
            abi.encodeWithSignature("receiveSecret(uint256)", secret)
        );
        require(ok2, "callback failed");
        emit Sent(msg.sender, secret);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SHELLCODE LOADER (DELEGATECALL TO EXTERNAL LIB)
//    Loads arbitrary logic via delegatecall()
////////////////////////////////////////////////////////////////////////////////
contract ShellcodeLoaderVuln {
    /// ❌ No whitelist – any lib may be loaded
    function load(address lib, bytes calldata data) external payable returns (bytes memory) {
        (bool ok, bytes memory ret) = lib.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}

/// Attack: deploy malicious lib then call load()
contract Attack_ShellcodeLoad {
    ShellcodeLoaderVuln public target;
    address                 public evilLib;

    constructor(ShellcodeLoaderVuln _t, address _evilLib) {
        target  = _t;
        evilLib = _evilLib;
    }

    function hack(bytes calldata data) external payable {
        target.load{value: msg.value}(evilLib, data);
    }
}

contract ShellcodeLoaderSafe {
    address public immutable owner;
    mapping(address => bool) public approved;

    event Approved(address lib);

    constructor(address[] memory libs) {
        owner = msg.sender;
        for (uint i; i < libs.length; i++) approved[libs[i]] = true;
    }

    /// Owner may whitelist new libs
    function approveLib(address lib) external {
        if (msg.sender != owner) revert Loader__NotOwner();
        approved[lib] = true;
        emit Approved(lib);
    }

    /// ✅ Only approved libs may be used
    function load(address lib, bytes calldata data) external payable returns (bytes memory) {
        if (!approved[lib]) revert Loader__NotApproved();
        (bool ok, bytes memory ret) = lib.delegatecall(data);
        require(ok, "delegatecall failed");
        return ret;
    }
}
