import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SingleActiveCall is ReentrancyGuard {
    bool private inCall;

    modifier oneAtATime() {
        require(!inCall, "[CAC] Another call in progress");
        inCall = true;
        _;
        inCall = false;
    }

    function criticalAction() external oneAtATime nonReentrant {
        // do something
    }
}
