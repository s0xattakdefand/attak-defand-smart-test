import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureVerifier {
    using ECDSA for bytes32;

    function verify(
        address expectedSigner,
        bytes32 messageHash,
        bytes calldata signature
    ) external pure returns (bool) {
        return messageHash.toEthSignedMessageHash().recover(signature) == expectedSigner;
    }
}
