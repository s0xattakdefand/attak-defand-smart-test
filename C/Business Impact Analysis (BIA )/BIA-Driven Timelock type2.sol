import "@openzeppelin/contracts/governance/TimelockController.sol";

contract BIAAwareTimelock is TimelockController {
    mapping(bytes32 => uint8) public moduleImpact;

    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors
    ) TimelockController(minDelay, proposers, executors, msg.sender) {}

    function setModuleImpact(bytes32 modId, uint8 score) external onlyRole(TIMELOCK_ADMIN_ROLE) {
        moduleImpact[modId] = score;
    }

    // use `moduleImpact[modId]` to auto-lower minDelay if needed
}
