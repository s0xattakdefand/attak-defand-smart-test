import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureIntegrity {
    using ECDSA for bytes32;

    function verify(address user, bytes calldata sig) external pure returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(user)).toEthSignedMessageHash();
        return hash.recover(sig) == user;
    }
}
