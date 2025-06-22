interface IBitGuardWithPreimage {
    function provePreimage(string calldata secret) external;
    function adminAction() external;
    function revoke(address user) external;
}

contract AutoSimPreimageLoop {
    event ActionSimulated(address user, string secret, bool success);

    function runLoop(address bitGuard, string calldata secret) external {
        IBitGuardWithPreimage(bitGuard).provePreimage(secret);
        try IBitGuardWithPreimage(bitGuard).adminAction() {
            emit ActionSimulated(msg.sender, secret, true);
        } catch {
            emit ActionSimulated(msg.sender, secret, false);
        }
        IBitGuardWithPreimage(bitGuard).revoke(msg.sender);
    }
}
