// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ContextOfUseValidator {
    bytes32 public constant DOMAIN_HASH = keccak256("App:Governance-v1:chain-1:dao.eth");

    mapping(bytes32 => bool) public usedHashes;

    event ValidContext(bytes32 indexed contextHash, address indexed actor);
    event InvalidContext(bytes32 indexed contextHash);

    function validate(bytes calldata payload, bytes calldata signature) external returns (bool) {
        bytes32 hash = keccak256(abi.encodePacked(DOMAIN_HASH, payload));
        require(!usedHashes[hash], "Context replayed");

        address signer = recover(hash, signature);
        if (signer != address(0)) {
            usedHashes[hash] = true;
            emit ValidContext(hash, signer);
            return true;
        }

        emit InvalidContext(hash);
        return false;
    }

    function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = split(sig);
        return ecrecover(toEthSignedMessageHash(hash), v, r, s);
    }

    function split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}
