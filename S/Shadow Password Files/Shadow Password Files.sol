// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

// Shared errors
error SHS__BadPassword();
error SSS__BadPassword();
error SIS__BadPassword();
error SPS__NotOwner();
error SPS__BadPassword();

//////////////////////////////////////////////////////////////
// 1. Plain‑Text Shadow Files
//////////////////////////////////////////////////////////////
contract ShadowPlainVuln {
    mapping(address => string) public shadow; 
    function setPassword(string calldata pw) external {
        shadow[msg.sender] = pw;
    }
}

contract Attack_ShadowPlain {
    ShadowPlainVuln public target;
    constructor(ShadowPlainVuln _t) { target = _t; }
    function steal(address user) external view returns (string memory) {
        return target.shadow(user);
    }
}

contract ShadowHashSafe {
    mapping(address => bytes32) private shadowHash;
    event PasswordSet(address indexed user);

    function setPassword(string calldata pw) external {
        shadowHash[msg.sender] = keccak256(abi.encodePacked(pw));
        emit PasswordSet(msg.sender);
    }

    function validatePassword(string calldata pw) external view returns (bool) {
        if (shadowHash[msg.sender] != keccak256(abi.encodePacked(pw))) revert SHS__BadPassword();
        return true;
    }
}

//////////////////////////////////////////////////////////////
// 2. Unsalted‑Hash Shadow Files
//////////////////////////////////////////////////////////////
contract ShadowHashVuln {
    mapping(address => bytes32) public shadowHash;
    function setPassword(bytes calldata pw) external {
        shadowHash[msg.sender] = keccak256(pw);
    }
}

contract Attack_ShadowHash {
    ShadowHashVuln public target;
    constructor(ShadowHashVuln _t) { target = _t; }
    function steal(address user) external view returns (bytes32) {
        return target.shadowHash(user);
    }
}

contract ShadowSaltSafe {
    mapping(address => bytes32) private shadowHash;
    mapping(address => bytes32) private salt;
    event PasswordSet(address indexed user);

    function setPassword(string calldata pw) external {
        bytes32 s = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        salt[msg.sender] = s;
        shadowHash[msg.sender] = keccak256(abi.encodePacked(pw, s));
        emit PasswordSet(msg.sender);
    }

    function validatePassword(string calldata pw) external view returns (bool) {
        if (shadowHash[msg.sender] != keccak256(abi.encodePacked(pw, salt[msg.sender]))) 
            revert SSS__BadPassword();
        return true;
    }
}

//////////////////////////////////////////////////////////////
// 3. Salted‑Hash Shadow Files
//////////////////////////////////////////////////////////////
contract ShadowSaltedVuln {
    mapping(address => bytes32) public shadowHash;
    mapping(address => bytes32) public salt;
    function setPassword(string calldata pw) external {
        bytes32 s = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        salt[msg.sender] = s;
        shadowHash[msg.sender] = keccak256(abi.encodePacked(pw, s));
    }
}

contract Attack_ShadowSalt {
    ShadowSaltedVuln public target;
    constructor(ShadowSaltedVuln _t) { target = _t; }
    function brute(address user) external view returns (bytes32 h, bytes32 s) {
        h = target.shadowHash(user);
        s = target.salt(user);
    }
}

contract ShadowIterSafe {
    mapping(address => bytes32) private shadowHash;
    mapping(address => bytes32) private salt;
    uint256 public constant ITER = 1000;
    event PasswordSet(address indexed user);

    function setPassword(string calldata pw) external {
        bytes32 s = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        salt[msg.sender] = s;
        bytes32 h = keccak256(abi.encodePacked(pw, s));
        for (uint i = 0; i < ITER; ++i) {
            h = keccak256(abi.encodePacked(h));
        }
        shadowHash[msg.sender] = h;
        emit PasswordSet(msg.sender);
    }

    function validatePassword(string calldata pw) external view returns (bool) {
        bytes32 h = keccak256(abi.encodePacked(pw, salt[msg.sender]));
        for (uint i = 0; i < ITER; ++i) {
            h = keccak256(abi.encodePacked(h));
        }
        if (shadowHash[msg.sender] != h) revert SIS__BadPassword();
        return true;
    }
}

//////////////////////////////////////////////////////////////
// 4. Iterated‑Salt Shadow Files
//////////////////////////////////////////////////////////////
contract ShadowIterVuln {
    mapping(address => bytes32) public shadowHash;
    mapping(address => bytes32) public salt;
    uint256 public constant ITER = 1000;
    function setPassword(string calldata pw) external {
        bytes32 s = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        salt[msg.sender] = s;
        bytes32 h = keccak256(abi.encodePacked(pw, s));
        for (uint i = 0; i < ITER; ++i) {
            h = keccak256(abi.encodePacked(h));
        }
        shadowHash[msg.sender] = h;
    }
}

contract Attack_ShadowIter {
    ShadowIterVuln public target;
    constructor(ShadowIterVuln _t) { target = _t; }
    function steal(address user) external view returns (bytes32 h, bytes32 s) {
        h = target.shadowHash(user);
        s = target.salt(user);
    }
}

contract ShadowPrivateSafe {
    mapping(address => bytes32) private shadowHash;
    mapping(address => bytes32) private salt;
    address public owner;
    event PasswordSet(address indexed user);

    constructor() {
        owner = msg.sender;
    }

    function setPassword(string calldata pw) external {
        bytes32 s = keccak256(abi.encodePacked(msg.sender, block.timestamp));
        salt[msg.sender] = s;
        bytes32 h = keccak256(abi.encodePacked(pw, s));
        for (uint i = 0; i < ITER; ++i) {
            h = keccak256(abi.encodePacked(h));
        }
        shadowHash[msg.sender] = h;
        emit PasswordSet(msg.sender);
    }

    function validatePassword(address user, string calldata pw) external view returns (bool) {
        if (msg.sender != owner) revert SPS__NotOwner();
        bytes32 h = keccak256(abi.encodePacked(pw, salt[user]));
        for (uint i = 0; i < ITER; ++i) {
            h = keccak256(abi.encodePacked(h));
        }
        if (shadowHash[user] != h) revert SPS__BadPassword();
        return true;
    }
}
