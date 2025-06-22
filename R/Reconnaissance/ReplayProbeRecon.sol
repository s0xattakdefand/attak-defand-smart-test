import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract ReplayProbeRecon {
    using ECDSA for bytes32;

    mapping(bytes32 => bool) public used;

    event ReplayDetected(address signer, bytes32 hash);

    function replayProbe(bytes32 hash, bytes calldata sig) external {
        address signer = hash.toEthSignedMessageHash().recover(sig);
        require(!used[hash], "Used");
        emit ReplayDetected(signer, hash);
    }
}
