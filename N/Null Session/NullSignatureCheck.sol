import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract NullSignatureCheck {
    using ECDSA for bytes32;

    function claim(bytes32 hash, bytes calldata sig) external {
        address signer = hash.toEthSignedMessageHash().recover(sig);
        require(signer != address(0), "Null signer"); // ❌ No known signer validation
    }
}
