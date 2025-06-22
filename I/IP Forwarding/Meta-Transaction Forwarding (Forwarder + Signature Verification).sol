pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MetaTxForwarder {
    using ECDSA for bytes32;
    mapping(bytes32 => bool) public executed;

    function forwardMetaTx(
        address user,
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes memory sig
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(user, target, data, nonce));
        require(!executed[hash], "Replay");
        require(hash.toEthSignedMessageHash().recover(sig) == user, "Invalid sig");

        executed[hash] = true;
        (bool success, ) = target.call(data);
        require(success, "Forward failed");
    }
}
