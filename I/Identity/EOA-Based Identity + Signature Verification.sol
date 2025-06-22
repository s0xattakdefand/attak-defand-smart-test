import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract IdentityVerifier {
    using ECDSA for bytes32;

    function verifyIdentity(address user, bytes32 dataHash, bytes calldata signature) external pure returns (bool) {
        return dataHash.toEthSignedMessageHash().recover(signature) == user;
    }
}
