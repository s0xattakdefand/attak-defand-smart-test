import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract MultiSigChecksum {
    using ECDSA for bytes32;

    mapping(address => bool) public signers;
    uint256 public minSigners;
    bytes32 public finalChecksum;

    event ChecksumMultiSigned(bytes32 newChecksum);

    constructor(address[] memory _signers, uint256 _minSigners) {
        minSigners = _minSigners;
        for (uint i = 0; i < _signers.length; i++) {
            signers[_signers[i]] = true;
        }
    }

    function updateChecksumMulti(
        bytes32 newChecksum,
        bytes[] calldata sigs,
        address[] calldata signersUsed
    ) external {
        require(sigs.length == signersUsed.length, "Mismatched arrays");
        uint256 count;
        bytes32 msgHash = keccak256(abi.encodePacked(newChecksum, address(this)))
            .toEthSignedMessageHash();

        for (uint i = 0; i < signersUsed.length; i++) {
            if (signers[signersUsed[i]]) {
                address recovered = msgHash.recover(sigs[i]);
                if (recovered == signersUsed[i]) {
                    count++;
                }
            }
        }
        require(count >= minSigners, "Not enough valid signers");

        finalChecksum = newChecksum;
        emit ChecksumMultiSigned(newChecksum);
    }
}
