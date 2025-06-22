function triggerLoop() external {
    routerA.forwardFromB(100); // Gas grief via infinite delegation
}
