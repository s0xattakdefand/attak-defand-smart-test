// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AuthorizationServer {
    address public admin;
    mapping(address => bool) public authorized;
    mapping(bytes32 => bool) public usedNonces;

    bytes32 public DOMAIN_SEPARATOR;
    bytes32 public constant AUTH_TYPEHASH = keccak256("Auth(address user,address target,uint256 expires,bytes32 nonce)");

    event Authorized(address indexed user);
    event AccessGranted(address indexed user, address indexed target);
    event NonceUsed(bytes32 indexed nonce);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("AuthServer"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    function setAuthorized(address user, bool status) external onlyAdmin {
        authorized[user] = status;
        emit Authorized(user);
    }

    function isAuthorized(address user) external view returns (bool) {
        return authorized[user];
    }

    function verifyAuthSignature(
        address user,
        address target,
        uint256 expires,
        bytes32 nonce,
        bytes calldata sig
    ) public returns (bool) {
        require(!usedNonces[nonce], "Nonce used");
        require(block.timestamp <= expires, "Signature expired");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(AUTH_TYPEHASH, user, target, expires, nonce))
            )
        );

        (bytes32 r, bytes32 s, uint8 v) = _splitSig(sig);
        address signer = ecrecover(digest, v, r, s);
        require(signer == user, "Invalid signer");

        usedNonces[nonce] = true;
        emit NonceUsed(nonce);
        emit AccessGranted(user, target);
        return true;
    }

    function _splitSig(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad signature");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
