pragma solidity ^0.8.0;

/**
 * @title DerivedTestRequirement
 * @dev A smart contract demonstrating test-derived requirements with ownership and input validation.
 * Requirements:
 * - Constructor must receive a valid non-zero address for initial owner.
 * - Only the owner can call restricted functions.
 * - Functions revert on invalid inputs to ensure security and reliability.
 */
contract DerivedTestRequirement {
    // State variable to store the owner's address
    address private contractOwner;

    // Event emitted when ownership is transferred
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Constructor with a require statement to ensure a valid owner address.
     * Test Requirement: Revert if the provided owner address is zero.
     */
    constructor(address _initialOwner) {
        require(_initialOwner != address(0), "Initial owner cannot be the zero address");
        contractOwner = _initialOwner;
        emit OwnershipTransferred(address(0), _initialOwner);
    }

    /**
     * @dev Modifier to restrict functions to only the contract owner.
     * Test Requirement: Ensure only the owner can call restricted functions.
     */
    modifier onlyOwner() {
        require(msg.sender == contractOwner, "Caller is not the owner");
        _;
    }

    /**
     * @dev Allows the owner to transfer ownership to a new address.
     * @param _newOwner The address to transfer ownership to.
     * Test Requirement: Revert if the new owner address is zero.
     * Test Requirement: Only the current owner can call this function.
     */
    function transferOwnership(address _newOwner) public onlyOwner {
        require(_newOwner != address(0), "New owner cannot be the zero address");
        address oldOwner = contractOwner;
        contractOwner = _newOwner;
        emit OwnershipTransferred(oldOwner, _newOwner);
    }

    /**
     * @dev Returns the address of the current owner.
     * @return The address of the contract owner.
     * Test Requirement: Ensure the returned address matches the stored owner.
     */
    function getContractOwner() public view returns (address) {
        return contractOwner;
    }

    /**
     * @dev Checks if the provided address is the contract owner.
     * @param _address The address to check.
     * @return bool True if the address is the owner, false otherwise.
     * Test Requirement: Return true only for the current owner's address.
     */
    function isContractOwner(address _address) public view returns (bool) {
        return _address == contractOwner;
    }

    /**
     * @dev Example function to demonstrate a restricted action.
     * Test Requirement: Only the owner can call this function.
     */
    function restrictedAction() public onlyOwner {
        // Example action: Could be used to test owner-only functionality
    }
}