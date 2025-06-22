// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureMasquerade {
    using ECDSA for bytes32;
    mapping(bytes32 => bool) public used;

    function submit(address victim, uint256 amount, uint256 nonce, bytes memory sig) external {
        bytes32 hash = keccak256(abi.encodePacked(victim, amount, nonce));
        address recovered = hash.toEthSignedMessageHash().recover(sig);
        require(recovered == victim, "Invalid signature");
        require(!used[hash], "Replay");

        used[hash] = true;
        payable(msg.sender).transfer(amount); // 🧨 impersonation via stolen sig
    }

    receive() external payable {}
}
