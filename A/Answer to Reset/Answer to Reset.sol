// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract AnswerToReset {
    string public version;
    bytes32 public identityHash;
    bytes4[] public supportedInterfaces;

    address public admin;
    event ATR(bytes32 identityHash, string version, bytes4[] interfaces);
    event ResetPerformed(address by, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor(string memory _version, bytes4[] memory _interfaces) {
        version = _version;
        supportedInterfaces = _interfaces;
        admin = msg.sender;
        identityHash = keccak256(abi.encodePacked(_version, _interfaces, address(this), block.chainid));
        emit ATR(identityHash, version, supportedInterfaces);
    }

    function resetATR(string calldata _newVersion, bytes4[] calldata _newInterfaces) external onlyAdmin {
        version = _newVersion;
        supportedInterfaces = _newInterfaces;
        identityHash = keccak256(abi.encodePacked(_newVersion, _newInterfaces, address(this), block.chainid));
        emit ResetPerformed(msg.sender, block.timestamp);
        emit ATR(identityHash, _newVersion, _newInterfaces);
    }

    function getATR() external view returns (bytes32, string memory, bytes4[] memory) {
        return (identityHash, version, supportedInterfaces);
    }
}
