// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: EOA Spoofing, Contract Impersonation, MetaTx Replay
/// Defense Types: Code Size Check, Account Whitelisting, Signature Guard

contract AccountSecurity {
    address public admin;
    mapping(address => bool) public contractWhitelist;
    mapping(address => uint256) public nonce;

    event AccountAccessGranted(address indexed account, string kind);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    /// DEFENSE: Register contract account whitelist
    function whitelistContract(address contractAccount) external onlyAdmin {
        require(_isContract(contractAccount), "Must be contract");
        contractWhitelist[contractAccount] = true;
    }

    /// DEFENSE: Detect EOA vs Contract
    function detectAccountType(address account) public view returns (string memory) {
        return _isContract(account) ? "CONTRACT" : "EOA";
    }

    /// DEFENSE: Access only EOAs
    function onlyEOA() external {
        require(!_isContract(msg.sender), "Contract calls not allowed");
        emit AccountAccessGranted(msg.sender, "EOA");
    }

    /// DEFENSE: Access only from whitelisted contracts
    function onlyWhitelistedContract() external {
        require(_isContract(msg.sender), "Must be contract");
        require(contractWhitelist[msg.sender], "Contract not approved");
        emit AccountAccessGranted(msg.sender, "CONTRACT");
    }

    /// DEFENSE: Meta Account simulated flow with nonce
    function executeMetaAction(uint256 userNonce, bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, userNonce));
        bytes32 signed = ECDSA.toEthSignedMessageHash(hash);
        address signer = ECDSA.recover(signed, signature);

        require(signer == msg.sender, "Invalid signature");
        require(nonce[msg.sender] == userNonce, "Replay detected");

        nonce[msg.sender]++;
        emit AccountAccessGranted(msg.sender, "META");
    }

    /// ATTACK Simulation: Contract calls EOA-restricted function
    function attackViaContract() external {
        if (_isContract(msg.sender)) {
            emit AttackDetected(msg.sender, "Contract impersonation attempt");
            revert("Blocked contract impersonation");
        }
    }

    /// Internal: EOA vs contract detector
    function _isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }
}

/// ECDSA lib (standalone)
library ECDSA {
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "Invalid sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }

        return ecrecover(hash, v, r, s);
    }
}
