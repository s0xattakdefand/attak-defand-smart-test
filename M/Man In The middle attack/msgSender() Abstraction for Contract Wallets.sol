// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

abstract contract MsgSenderContext {
    function _msgSender() internal view virtual returns (address sender) {
        if (msg.sender == address(this)) {
            assembly {
                sender := shr(96, calldataload(sub(calldatasize(), 20)))
            }
        } else {
            sender := msg.sender;
        }
    }
}

contract ContractWalletCompatible is MsgSenderContext {
    mapping(address => uint256) public balance;

    function metaTransfer() external payable {
        address sender = _msgSender();
        balance[sender] += msg.value;
    }
}
