import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SignedCustody {
    using ECDSA for bytes32;

    mapping(bytes32 => address) public holder;

    event CustodyTransfer(bytes32 itemId, address from, address to);

    function transferWithSig(
        bytes32 itemId,
        address newHolder,
        uint256 nonce,
        bytes calldata sig
    ) external {
        // message: (itemId, newHolder, nonce, thisContract)
        bytes32 hash = keccak256(abi.encodePacked(itemId, newHolder, nonce, address(this)))
            .toEthSignedMessageHash();

        address currentHolder = holder[itemId];
        // The signature must come from current holder
        require(hash.recover(sig) == currentHolder, "Invalid signature");
        
        holder[itemId] = newHolder;
        emit CustodyTransfer(itemId, currentHolder, newHolder);
    }
}
