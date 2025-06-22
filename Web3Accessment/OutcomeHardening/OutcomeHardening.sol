// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title OutcomeHardenedFrontEndAttackDefense - Hardened Web3 Frontend Defense Simulation via Smart Contract Safeguards
/// @author ChatGPT

/// @notice Secure smart contract forcing safe transaction confirmation patterns
contract OutcomeHardenedWeb3Contract {
    address public immutable contractAddress;
    address public immutable owner;
    mapping(address => uint256) public userNonces;

    event SafeTransactionExecuted(address indexed user, uint256 indexed nonce, string action);

    constructor() {
        owner = msg.sender;
        contractAddress = address(this);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function safeExecute(
        string calldata actionName,
        uint256 expectedNonce,
        address targetContract,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(targetContract == contractAddress, "Invalid contract target (Phishing Protection)");
        require(expectedNonce == userNonces[msg.sender], "Nonce mismatch");

        bytes32 digest = keccak256(
            abi.encodePacked(msg.sender, expectedNonce, actionName, targetContract)
        );
        bytes32 ethSignedDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));

        address recovered = ecrecover(ethSignedDigest, v, r, s);
        require(recovered == msg.sender, "Signature invalid");

        userNonces[msg.sender] += 1;

        emit SafeTransactionExecuted(msg.sender, expectedNonce, actionName);
    }

    function getNonce(address user) external view returns (uint256) {
        return userNonces[user];
    }
}

/// @notice Attack contract trying to bypass safe transaction verification
contract FrontendHijackIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    // Try to execute transaction to wrong contract
    function tryFakeExecute(
        address victim,
        uint256 fakeNonce,
        string calldata fakeAction,
        address wrongTarget,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature(
                "safeExecute(string,uint256,address,uint8,bytes32,bytes32)",
                fakeAction,
                fakeNonce,
                wrongTarget,
                v,
                r,
                s
            )
        );
    }
}
