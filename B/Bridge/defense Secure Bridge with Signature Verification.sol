// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureBridge {
    using ECDSA for bytes32;

    IERC20 public token;
    address public signer;

    event BridgedOut(address indexed user, uint256 amount, string destinationChain);
    event BridgedIn(address indexed user, uint256 amount, string sourceChain);

    mapping(bytes32 => bool) public processed;

    constructor(address _token, address _signer) {
        token = IERC20(_token);
        signer = _signer;
    }

    function bridgeOut(uint256 amount, string calldata destinationChain) external {
        token.transferFrom(msg.sender, address(this), amount);
        emit BridgedOut(msg.sender, amount, destinationChain);
    }

    function bridgeIn(
        address user,
        uint256 amount,
        string calldata sourceChain,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(user, amount, sourceChain, nonce));
        bytes32 signedHash = hash.toEthSignedMessageHash();
        require(signedHash.recover(signature) == signer, "Invalid signature");
        require(!processed[signedHash], "Already processed");

        processed[signedHash] = true;
        token.transfer(user, amount);

        emit BridgedIn(user, amount, sourceChain);
    }
}
