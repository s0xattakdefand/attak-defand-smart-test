pragma solidity ^0.8.21;

interface INFT {
    function mint() external payable;
}

contract LegionSniper {
    address public target;
    address public commander;

    constructor(address _target) {
        target = _target;
        commander = msg.sender;
    }

    function snipe() external payable {
        INFT(target).mint{value: msg.value}();
    }

    function selfDestruct() external {
        require(msg.sender == commander, "Not authorized");
        selfdestruct(payable(commander));
    }
}
