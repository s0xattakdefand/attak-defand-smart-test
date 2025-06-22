// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract HostSignatureVerifier {
    using ECDSA for bytes32;

    address public trustedHost;

    constructor(address _trustedHost) {
        trustedHost = _trustedHost;
    }

    function verify(bytes32 msgHash, bytes calldata sig) external view returns (bool) {
        return msgHash.toEthSignedMessageHash().recover(sig) == trustedHost;
    }
}
