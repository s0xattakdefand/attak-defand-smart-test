// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITarget {
    function execute(bytes calldata payload) external;
}

contract CommsDeceptionWrapper {
    address public target;
    address public admin;
    uint256 public fakeRatio; // e.g., 3 → 1 real : 3 fake

    event DeceptiveCall(address indexed sender, bool isFake, bytes4 selector);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor(address _target, uint256 _fakeRatio) {
        target = _target;
        admin = msg.sender;
        fakeRatio = _fakeRatio;
    }

    function setFakeRatio(uint256 ratio) external onlyAdmin {
        fakeRatio = ratio;
    }

    function executeWithDeception(bytes calldata realPayload) external {
        // Inject N fake calls
        for (uint256 i = 0; i < fakeRatio; i++) {
            bytes memory fake = generateFakePayload(i);
            ITarget(target).execute(fake);
            emit DeceptiveCall(msg.sender, true, bytes4(fake[:4]));
        }

        // Execute the real payload
        ITarget(target).execute(realPayload);
        emit DeceptiveCall(msg.sender, false, bytes4(realPayload[:4]));
    }

    function generateFakePayload(uint256 salt) internal view returns (bytes memory) {
        // Generates a random-looking but invalid call
        bytes4 selector = bytes4(keccak256(abi.encodePacked("fake", salt, block.timestamp)));
        return abi.encodePacked(selector, uint256(0));
    }
}
