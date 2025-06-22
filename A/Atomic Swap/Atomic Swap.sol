// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AtomicSwapHTLC - A trustless atomic swap using hash-time-locked contracts (HTLC)

contract AtomicSwapHTLC {
    struct Swap {
        address sender;
        address receiver;
        uint256 amount;
        bytes32 hashlock;      // keccak256(secret)
        uint256 timelock;      // block.timestamp + duration
        bool withdrawn;
        bool refunded;
        bytes32 preimage;
    }

    mapping(bytes32 => Swap) public swaps;

    event Initiated(bytes32 indexed swapID, address indexed sender, address receiver);
    event Withdrawn(bytes32 indexed swapID, bytes32 preimage);
    event Refunded(bytes32 indexed swapID);

    modifier onlySender(bytes32 _id) {
        require(msg.sender == swaps[_id].sender, "Not sender");
        _;
    }

    modifier onlyReceiver(bytes32 _id) {
        require(msg.sender == swaps[_id].receiver, "Not receiver");
        _;
    }

    function initiateSwap(
        bytes32 _swapID,
        address _receiver,
        bytes32 _hashlock,
        uint256 _duration
    ) external payable {
        require(swaps[_swapID].sender == address(0), "Swap exists");
        require(msg.value > 0, "No ETH sent");

        swaps[_swapID] = Swap({
            sender: msg.sender,
            receiver: _receiver,
            amount: msg.value,
            hashlock: _hashlock,
            timelock: block.timestamp + _duration,
            withdrawn: false,
            refunded: false,
            preimage: 0x0
        });

        emit Initiated(_swapID, msg.sender, _receiver);
    }

    function withdraw(bytes32 _swapID, bytes32 _preimage) external onlyReceiver(_swapID) {
        Swap storage s = swaps[_swapID];
        require(!s.withdrawn, "Already withdrawn");
        require(!s.refunded, "Already refunded");
        require(block.timestamp <= s.timelock, "Expired");
        require(keccak256(abi.encodePacked(_preimage)) == s.hashlock, "Invalid preimage");

        s.withdrawn = true;
        s.preimage = _preimage;
        payable(s.receiver).transfer(s.amount);
        emit Withdrawn(_swapID, _preimage);
    }

    function refund(bytes32 _swapID) external onlySender(_swapID) {
        Swap storage s = swaps[_swapID];
        require(!s.withdrawn, "Already withdrawn");
        require(!s.refunded, "Already refunded");
        require(block.timestamp > s.timelock, "Not expired");

        s.refunded = true;
        payable(s.sender).transfer(s.amount);
        emit Refunded(_swapID);
    }

    function getSwap(bytes32 _swapID) external view returns (Swap memory) {
        return swaps[_swapID];
    }
}
