// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IDtcExtension
 * @dev Interface for modular extensions in DTC (e.g., compliance, yield optimization).
 * Extensions can be attached to DtcContainer for upgradable functionality.
 */
interface IDtcExtension {
    /**
     * @dev Execute extension-specific logic.
     * @param data Arbitrary calldata for the extension's operation.
     * @return result Bytes-encoded result from the extension.
     */
    function execute(bytes calldata data) external returns (bytes memory result);
}