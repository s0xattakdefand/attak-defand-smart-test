import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignatureDriftReplay {
    using ECDSA for bytes32;
    mapping(bytes32 => bool) public used;

    event Executed(address signer);

    function replay(bytes32 hash, bytes calldata sig) external {
        require(!used[hash], "Used");
        address signer = hash.toEthSignedMessageHash().recover(sig);
        require(signer != address(0), "Invalid sig");
        used[hash] = true;
        emit Executed(signer);
    }
}
