// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MetaTxRelayerBastion {
    using ECDSA for bytes32;

    address public backendSigner;
    IERC20 public tokenContract;

    mapping(address => uint256) public latestNonce;

    event Relayed(address indexed user, uint256 amount, uint256 nonce);

    constructor(address _token, address _signer) {
        tokenContract = IERC20(_token);
        backendSigner = _signer;
    }

    /**
     * @notice Relays a token transfer authorized via off-chain signature.
     * @param user The original signer/user.
     * @param amount The amount of tokens to transfer.
     * @param nonce A unique number to prevent replay.
     * @param sig The off-chain signature from backendSigner.
     */
    function relay(
        address user,
        uint256 amount,
        uint256 nonce,
        bytes calldata sig
    ) public {
        require(nonce > latestNonce[user], "Nonce too old or reused");

        bytes32 hash = keccak256(abi.encodePacked(user, amount, nonce));
        bytes32 messageHash = hash.toEthSignedMessageHash();

        require(
            messageHash.recover(sig) == backendSigner,
            "Invalid signature"
        );

        latestNonce[user] = nonce;

        // Relay the token transfer on behalf of the user
        require(
            tokenContract.transferFrom(user, msg.sender, amount),
            "Token transfer failed"
        );

        emit Relayed(user, amount, nonce);
    }
}
