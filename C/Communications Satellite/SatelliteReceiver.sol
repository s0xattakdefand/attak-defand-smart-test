contract SatelliteReceiver {
    address public satellite;

    modifier onlySatellite() {
        require(msg.sender == satellite, "Invalid source");
        _;
    }

    constructor(address _satellite) {
        satellite = _satellite;
    }

    function receivePayload(bytes calldata payload) external onlySatellite {
        // Decode and apply the payload
    }
}
