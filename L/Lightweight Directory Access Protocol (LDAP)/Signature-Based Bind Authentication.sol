pragma solidity ^0.8.21;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureBindAuth {
    using ECDSA for bytes32;
    address public verifier;

    constructor(address _verifier) {
        verifier = _verifier;
    }

    function bindAuth(string memory identity, uint256 timestamp, bytes memory sig) external view returns (bool) {
        bytes32 digest = keccak256(abi.encodePacked(identity, timestamp));
        bytes32 ethDigest = digest.toEthSignedMessageHash();
        return ethDigest.recover(sig) == verifier;
    }
}
