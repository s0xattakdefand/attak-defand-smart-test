interface IZeroDayTracker {
    function register(bytes4 selector, address origin) external;
}

contract ZeroDaySync {
    IZeroDayTracker public zeroDay;

    constructor(address _tracker) {
        zeroDay = IZeroDayTracker(_tracker);
    }

    function push(bytes4 sel) external {
        zeroDay.register(sel, msg.sender);
    }
}
