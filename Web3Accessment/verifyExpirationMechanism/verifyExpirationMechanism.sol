// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ExpirationVerificationAttackDefense - Full Attack and Defense Simulation for Expiration Mechanisms in Web3 Contracts
/// @author ChatGPT

/// @notice Secure smart contract implementing strict expiration checks
contract SecureExpirationContract {
    address public owner;

    struct ActionAuthorization {
        address user;
        uint256 amount;
        uint256 expiresAt;
        bool used;
    }

    mapping(bytes32 => ActionAuthorization) public authorizations;

    event AuthorizationCreated(bytes32 indexed authId, address indexed user, uint256 amount, uint256 expiresAt);
    event AuthorizationUsed(bytes32 indexed authId);

    constructor() {
        owner = msg.sender;
    }

    function createAuthorization(address _user, uint256 _amount, uint256 _durationSeconds) external returns (bytes32 authId) {
        require(_durationSeconds > 0 && _durationSeconds <= 3600, "Invalid duration"); // max 1 hour
        require(_user != address(0), "Invalid user");

        authId = keccak256(
            abi.encodePacked(_user, _amount, block.timestamp, block.number)
        );

        authorizations[authId] = ActionAuthorization({
            user: _user,
            amount: _amount,
            expiresAt: block.timestamp + _durationSeconds,
            used: false
        });

        emit AuthorizationCreated(authId, _user, _amount, block.timestamp + _durationSeconds);
    }

    function useAuthorization(bytes32 _authId) external {
        ActionAuthorization storage auth = authorizations[_authId];

        require(auth.user == msg.sender, "Not authorized user");
        require(auth.expiresAt >= block.timestamp, "Authorization expired");
        require(!auth.used, "Already used");

        auth.used = true;

        emit AuthorizationUsed(_authId);
    }

    function verifyAuthorization(bytes32 _authId) external view returns (bool) {
        ActionAuthorization memory auth = authorizations[_authId];
        return (auth.user == msg.sender && auth.expiresAt >= block.timestamp && !auth.used);
    }
}

/// @notice Attack contract trying to reuse or bypass expiration checks
contract ExpirationIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryReuseAuthorization(bytes32 oldAuthId) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature("useAuthorization(bytes32)", oldAuthId)
        );
    }
}
