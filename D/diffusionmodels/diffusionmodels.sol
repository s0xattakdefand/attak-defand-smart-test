// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;

/**
 * @title DiffusionModels
 * @dev A smart contract for managing a decentralized marketplace for diffusion model outputs.
 * Supports model registration, content submission, and trading of generated outputs.
 * THIS IS AN EXAMPLE CONTRACT FOR EDUCATIONAL PURPOSES ONLY AND USES UN-AUDITED CODE.
 * DO NOT USE THIS CODE IN PRODUCTION.
 */
contract DiffusionModels {
    // Struct to represent a diffusion model
    struct Model {
        string modelName; // Name of the diffusion model
        string description; // Description of the model
        address owner; // Owner of the model
        bool isRegistered; // Flag to check if model is registered
    }

    // Struct to represent a generated output (e.g., image, data)
    struct Output {
        bytes32 outputHash; // Hash of the generated output (e.g., IPFS hash)
        string description; // Description of the output
        address creator; // Creator of the output
        uint256 modelId; // ID of the model used to generate the output
        uint256 price; // Price in wei for purchasing the output
        bool isAvailable; // Flag to check if output is available for purchase
    }

    // Mapping to store models by their unique ID
    mapping(uint256 => Model) public models;
    // Mapping to store outputs by their unique ID
    mapping(uint256 => Output) public outputs;
    // Counter for model IDs
    uint256 public modelCount;
    // Counter for output IDs
    uint256 public outputCount;

    // Event emitted when a new model is registered
    event ModelRegistered(uint256 indexed modelId, string modelName, address indexed owner);
    // Event emitted when a new output is submitted
    event OutputSubmitted(uint256 indexed outputId, bytes32 outputHash, uint256 indexed modelId, address indexed creator);
    // Event emitted when an output is purchased
    event OutputPurchased(uint256 indexed outputId, address indexed buyer, uint256 price);
    // Event emitted when an output's availability or price is updated
    event OutputUpdated(uint256 indexed outputId, bool isAvailable, uint256 price);

    // Modifier to check if the caller is the model owner
    modifier onlyModelOwner(uint256 modelId) {
        require(models[modelId].owner == msg.sender, "Only the model owner can perform this action");
        require(models[modelId].isRegistered, "Model does not exist");
        _;
    }

    // Modifier to check if the caller is the output creator
    modifier onlyOutputCreator(uint256 outputId) {
        require(outputs[outputId].creator == msg.sender, "Only the output creator can perform this action");
        require(outputs[outputId].isAvailable, "Output does not exist or is not available");
        _;
    }

    /**
     * @dev Registers a new diffusion model.
     * @param _modelName The name of the model.
     * @param _description The description of the model.
     * @return modelId The ID of the registered model.
     */
    function registerModel(string memory _modelName, string memory _description) public returns (uint256) {
        require(bytes(_modelName).length > 0, "Model name cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");

        modelCount++;
        Model storage newModel = models[modelCount];
        newModel.modelName = _modelName;
        newModel.description = _description;
        newModel.owner = msg.sender;
        newModel.isRegistered = true;

        // Emit event for model registration
        emit ModelRegistered(modelCount, _modelName, msg.sender);

        return modelCount;
    }

    /**
     * @dev Submits a new generated output from a diffusion model.
     * @param _outputHash The hash of the generated output (e.g., IPFS hash).
     * @param _description The description of the output.
     * @param _modelId The ID of the model used to generate the output.
     * @param _price The price in wei for purchasing the output.
     * @return outputId The ID of the submitted output.
     */
    function submitOutput(
        bytes32 _outputHash,
        string memory _description,
        uint256 _modelId,
        uint256 _price
    ) public returns (uint256) {
        require(models[_modelId].isRegistered, "Model does not exist");
        require(_outputHash != bytes32(0), "Output hash cannot be empty");
        require(bytes(_description).length > 0, "Description cannot be empty");
        require(_price >= 0, "Price cannot be negative");

        outputCount++;
        Output storage newOutput = outputs[outputCount];
        newOutput.outputHash = _outputHash;
        newOutput.description = _description;
        newOutput.creator = msg.sender;
        newOutput.modelId = _modelId;
        newOutput.price = _price;
        newOutput.isAvailable = true;

        // Emit event for output submission
        emit OutputSubmitted(outputCount, _outputHash, _modelId, msg.sender);

        return outputCount;
    }

    /**
     * @dev Purchases a generated output by paying the specified price.
     * @param _outputId The ID of the output to purchase.
     */
    function purchaseOutput(uint256 _outputId) public payable {
        require(outputs[_outputId].isAvailable, "Output does not exist or is not available");
        require(msg.value >= outputs[_outputId].price, "Insufficient payment");

        address creator = outputs[_outputId].creator;
        uint256 price = outputs[_outputId].price;

        // Mark output as unavailable
        outputs[_outputId].isAvailable = false;

        // Transfer payment to the creator
        (bool success, ) = creator.call{value: price}("");
        require(success, "Payment transfer failed");

        // Refund excess payment if any
        if (msg.value > price) {
            (bool refundSuccess, ) = msg.sender.call{value: msg.value - price}("");
            require(refundSuccess, "Refund transfer failed");
        }

        // Emit event for output purchase
        emit OutputPurchased(_outputId, msg.sender, price);
    }

    /**
     * @dev Updates the availability or price of an output.
     * @param _outputId The ID of the output.
     * @param _isAvailable The new availability status.
     * @param _newPrice The new price in wei.
     */
    function updateOutput(uint256 _outputId, bool _isAvailable, uint256 _newPrice) public onlyOutputCreator(_outputId) {
        require(_newPrice >= 0, "Price cannot be negative");
        outputs[_outputId].isAvailable = _isAvailable;
        outputs[_outputId].price = _newPrice;

        // Emit event for output update
        emit OutputUpdated(_outputId, _isAvailable, _newPrice);
    }

    /**
     * @dev Retrieves the details of a diffusion model.
     * @param _modelId The ID of the model.
     * @return modelName The name of the model.
     * @return description The description of the model.
     * @return owner The owner of the model.
     */
    function getModel(uint256 _modelId)
        public
        view
        returns (
            string memory modelName,
            string memory description,
            address owner
        )
    {
        require(models[_modelId].isRegistered, "Model does not exist");
        Model storage model = models[_modelId];
        return (model.modelName, model.description, model.owner);
    }

    /**
     * @dev Retrieves the details of a generated output.
     * @param _outputId The ID of the output.
     * @return outputHash The hash of the output.
     * @return description The description of the output.
     * @return creator The creator of the output.
     * @return modelId The ID of the model used.
     * @return price The price of the output.
     * @return isAvailable The availability status.
     */
    function getOutput(uint256 _outputId)
        public
        view
        returns (
            bytes32 outputHash,
            string memory description,
            address creator,
            uint256 modelId,
            uint256 price,
            bool isAvailable
        )
    {
        require(outputs[_outputId].isAvailable || outputs[_outputId].creator != address(0), "Output does not exist");
        Output storage output = outputs[_outputId];
        return (
            output.outputHash,
            output.description,
            output.creator,
            output.modelId,
            output.price,
            output.isAvailable
        );
    }
}