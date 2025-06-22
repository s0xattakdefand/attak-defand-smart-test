// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AuthenticationServer {
    address public admin;
    mapping(address => uint256) public nonces;

    bytes32 public constant AUTH_TYPEHASH = keccak256("Login(address user,uint256 expires,uint256 nonce)");
    bytes32 public DOMAIN_SEPARATOR;

    event Authenticated(address indexed user, uint256 indexed nonce, uint256 expires);

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

    function login(address user, uint256 expires, uint256 nonce, bytes calldata sig) external returns (bool) {
        require(block.timestamp <= expires, "Signature expired");
        require(nonce == nonces[user], "Invalid nonce");

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(AUTH_TYPEHASH, user, expires, nonce))
            )
        );

        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        address signer = ecrecover(digest, v, r, s);
        require(signer == user, "Invalid signer");

        nonces[user]++;
        emit Authenticated(user, nonce, expires);
        return true;
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad signature");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function getNonce(address user) external view returns (uint256) {
        return nonces[user];
    }
}
