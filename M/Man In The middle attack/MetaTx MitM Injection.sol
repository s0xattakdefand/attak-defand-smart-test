// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MetaTxMitM {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public usedHashes;

    event Executed(address from, address to, uint256 value);

    function relayMetaTx(
        address from,
        address to,
        uint256 value,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(from, to, value, nonce));
        require(!usedHashes[hash], "Already used");

        address recovered = hash.toEthSignedMessageHash().recover(signature);
        require(recovered == from, "Invalid signer");

        usedHashes[hash] = true;

        // 💥 MitM: attacker relays the tx to different 'to' address or value
        (bool success, ) = to.call{value: value}("");
        require(success, "Transfer failed");

        emit Executed(from, to, value);
    }

    receive() external payable {}
}
