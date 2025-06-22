pragma solidity ^0.8.21;

contract CurrencyValidation {
    mapping(string => bool) public supportedCurrency;

    constructor() {
        supportedCurrency["USD"] = true;
        supportedCurrency["EUR"] = true;
        supportedCurrency["BTC"] = true;
        supportedCurrency["ETH"] = true;
    }

    function isValidCurrency(string memory code) external view returns (bool) {
        return supportedCurrency[code];
    }
}
