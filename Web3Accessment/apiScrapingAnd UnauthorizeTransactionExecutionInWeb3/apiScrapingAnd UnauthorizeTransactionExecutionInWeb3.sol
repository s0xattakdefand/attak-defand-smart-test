// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title APIScrapingUnauthorizedExecutionAttackDefense - Attack and Defense Simulation for API Scraping and Unauthorized Transaction Execution in Web3
/// @author ChatGPT

/// @notice Secure contract defending against unauthorized API scraping and execution
contract SecureAPIExecution {
    address public owner;
    mapping(address => uint256) public nonces;

    event AuthorizedAction(address indexed user, uint256 indexed nonce, string actionDetails);

    constructor() {
        owner = msg.sender;
    }

    function performAuthorizedAction(
        uint256 userNonce,
        string calldata actionDetails,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        bytes32 message = keccak256(
            abi.encodePacked(msg.sender, userNonce, actionDetails, address(this))
        );

        bytes32 ethSignedMessage = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", message)
        );

        address signer = ecrecover(ethSignedMessage, v, r, s);
        require(signer == msg.sender, "Invalid signature");
        require(userNonce == nonces[msg.sender], "Invalid nonce");

        nonces[msg.sender] += 1;

        emit AuthorizedAction(msg.sender, userNonce, actionDetails);
    }

    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}

/// @notice Attack contract trying to scrape and replay unauthorized execution
contract APIScraperIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    // Try replaying an old valid signature
    function tryReplayAction(
        address victim,
        uint256 oldNonce,
        string calldata actionDetails,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success) {
        (success, ) = target.call(
            abi.encodeWithSignature(
                "performAuthorizedAction(uint256,string,uint8,bytes32,bytes32)",
                oldNonce,
                actionDetails,
                v,
                r,
                s
            )
        );
    }
}
