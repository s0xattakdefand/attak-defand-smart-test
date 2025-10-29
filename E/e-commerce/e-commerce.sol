// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title E-Commerce Smart Contract
 * @dev Complete decentralized e-commerce platform with:
 *      - Product listing
 *      - Order placement
 *      - Escrow payments
 *      - Shipping status
 *      - Dispute resolution
 *      - Seller ratings
 * @author Grok
 */
contract ECommerce {
    address public owner;
    uint256 public productCount;
    uint256 public orderCount;

    enum OrderStatus { Pending, Paid, Shipped, Delivered, Disputed, Refunded, Completed }

    struct Product {
        uint256 id;
        string name;
        string description;
        uint256 price; // in wei
        address payable seller;
        bool active;
        uint256 stock;
        string imageHash; // IPFS hash
    }

    struct Order {
        uint256 id;
        uint256 productId;
        address buyer;
        uint256 quantity;
        uint256 totalPrice;
        uint256 timestamp;
        OrderStatus status;
        string shippingAddress;
        uint256 deliveryTimestamp;
    }

    struct Seller {
        string name;
        string contact;
        uint256 totalSales;
        uint256 ratingSum;
        uint256 ratingCount;
        bool verified;
    }

    mapping(uint256 => Product) public products;
    mapping(uint256 => Order) public orders;
    mapping(address => Seller) public sellers;
    mapping(address => uint256[]) public sellerProducts;
    mapping(address => uint256[]) public buyerOrders;

    event ProductListed(
        uint256 indexed productId,
        string name,
        uint256 price,
        address indexed seller
    );

    event ProductUpdated(
        uint256 indexed productId,
        string name,
        uint256 price
    );

    event ProductDeactivated(uint256 indexed productId);

    event OrderPlaced(
        uint256 indexed orderId,
        uint256 indexed productId,
        address indexed buyer,
        uint256 quantity,
        uint256 totalPrice
    );

    event PaymentReleased(
        uint256 indexed orderId,
        address indexed seller,
        uint256 amount
    );

    event OrderShipped(uint256 indexed orderId, string tracking);

    event OrderDelivered(uint256 indexed orderId);

    event OrderDisputed(uint256 indexed orderId);

    event DisputeResolved(uint256 indexed orderId, bool buyerWon);

    event SellerRated(address indexed seller, uint256 rating);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlySeller(uint256 productId) {
        require(products[productId].seller == msg.sender, "Not seller");
        _;
    }

    modifier onlyBuyer(uint256 orderId) {
        require(orders[orderId].buyer == msg.sender, "Not buyer");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @dev Register or update seller profile
     * @param name Seller name
     * @param contact Contact info
     */
    function registerSeller(string memory name, string memory contact) public {
        require(bytes(name).length > 0, "Name required");
        sellers[msg.sender] = Seller({
            name: name,
            contact: contact,
            totalSales: sellers[msg.sender].totalSales,
            ratingSum: sellers[msg.sender].ratingSum,
            ratingCount: sellers[msg.sender].ratingCount,
            verified: sellers[msg.sender].verified
        });
    }

    /**
     * @dev List a new product
     * @param name Product name
     * @param description Product description
     * @param price Price in wei
     * @param stock Initial stock
     * @param imageHash IPFS hash of image
     */
    function listProduct(
        string memory name,
        string memory description,
        uint256 price,
        uint256 stock,
        string memory imageHash
    ) public returns (uint256) {
        require(bytes(name).length > 0, "Name required");
        require(price > 0, "Price > 0");
        require(stock > 0, "Stock > 0");

        productCount++;
        products[productCount] = Product({
            id: productCount,
            name: name,
            description: description,
            price: price,
            seller: payable(msg.sender),
            active: true,
            stock: stock,
            imageHash: imageHash
        });

        sellerProducts[msg.sender].push(productCount);
        emit ProductListed(productCount, name, price, msg.sender);
        return productCount;
    }

    /**
     * @dev Update product details
     * @param productId Product ID
     * @param name New name
     * @param description New description
     * @param price New price
     * @param stock New stock
     */
    function updateProduct(
        uint256 productId,
        string memory name,
        string memory description,
        uint256 price,
        uint256 stock
    ) public onlySeller(productId) {
        Product storage product = products[productId];
        require(product.active, "Product not active");

        product.name = name;
        product.description = description;
        product.price = price;
        product.stock = stock;

        emit ProductUpdated(productId, name, price);
    }

    /**
     * @dev Deactivate product
     * @param productId Product ID
     */
    function deactivateProduct(uint256 productId) public onlySeller(productId) {
        products[productId].active = false;
        emit ProductDeactivated(productId);
    }

    /**
     * @dev Place an order
     * @param productId Product ID
     * @param quantity Quantity
     * @param shippingAddress Buyer's address
     */
    function placeOrder(
        uint256 productId,
        uint256 quantity,
        string memory shippingAddress
    ) public payable {
        Product memory product = products[productId];
        require(product.active, "Product not active");
        require(quantity > 0 && quantity <= product.stock, "Invalid quantity");
        require(msg.value == product.price * quantity, "Incorrect payment");

        orderCount++;
        uint256 totalPrice = product.price * quantity;

        orders[orderCount] = Order({
            id: orderCount,
            productId: productId,
            buyer: msg.sender,
            quantity: quantity,
            totalPrice: totalPrice,
            timestamp: block.timestamp,
            status: OrderStatus.Paid,
            shippingAddress: shippingAddress,
            deliveryTimestamp: 0
        });

        // Reduce stock
        products[productId].stock -= quantity;
        buyerOrders[msg.sender].push(orderCount);

        emit OrderPlaced(orderCount, productId, msg.sender, quantity, totalPrice);
    }

    /**
     * @dev Mark order as shipped
     * @param orderId Order ID
     * @param tracking Tracking number
     */
    function shipOrder(uint256 orderId, string memory tracking) public {
        Order storage order = orders[orderId];
        Product memory product = products[order.productId];
        require(product.seller == msg.sender, "Not seller");
        require(order.status == OrderStatus.Paid, "Not paid");

        order.status = OrderStatus.Shipped;
        emit OrderShipped(orderId, tracking);
    }

    /**
     * @dev Confirm delivery and release payment
     * @param orderId Order ID
     */
    function confirmDelivery(uint256 orderId) public onlyBuyer(orderId) {
        Order storage order = orders[orderId];
        require(order.status == OrderStatus.Shipped, "Not shipped");

        order.status = OrderStatus.Delivered;
        order.deliveryTimestamp = block.timestamp;

        // Release payment to seller
        Product memory product = products[order.productId];
        product.seller.transfer(order.totalPrice);

        // Update seller stats
        sellers[product.seller].totalSales += order.totalPrice;

        emit PaymentReleased(orderId, product.seller, order.totalPrice);
        emit OrderDelivered(orderId);
    }

    /**
     * @dev Dispute an order
     * @param orderId Order ID
     */
    function disputeOrder(uint256 orderId) public onlyBuyer(orderId) {
        Order storage order = orders[orderId];
        require(
            order.status == OrderStatus.Paid || 
            order.status == OrderStatus.Shipped,
            "Cannot dispute"
        );

        order.status = OrderStatus.Disputed;
        emit OrderDisputed(orderId);
    }

    /**
     * @dev Resolve dispute (admin only)
     * @param orderId Order ID
     * @param buyerWins True if refund to buyer
     */
    function resolveDispute(uint256 orderId, bool buyerWins) public onlyOwner {
        Order storage order = orders[orderId];
        require(order.status == OrderStatus.Disputed, "Not disputed");

        if (buyerWins) {
            order.status = OrderStatus.Refunded;
            payable(order.buyer).transfer(order.totalPrice);
        } else {
            order.status = OrderStatus.Completed;
            Product memory product = products[order.productId];
            product.seller.transfer(order.totalPrice);
            sellers[product.seller].totalSales += order.totalPrice;
        }

        emit DisputeResolved(orderId, buyerWins);
    }

    /**
     * @dev Rate seller after delivery
     * @param seller Address of seller
     * @param rating 1-5 stars
     */
    function rateSeller(address seller, uint256 rating) public {
        require(rating >= 1 && rating <= 5, "Rating 1-5");
        require(buyerHasPurchased(msg.sender, seller), "No purchase");

        Seller storage s = sellers[seller];
        s.ratingSum += rating;
        s.ratingCount++;

        emit SellerRated(seller, rating);
    }

    /**
     * @dev Get seller rating
     * @param seller Seller address
     * @return average Average rating
     */
    function getSellerRating(address seller) public view returns (uint256 average) {
        Seller memory s = sellers[seller];
        if (s.ratingCount == 0) return 0;
        return s.ratingSum / s.ratingCount;
    }

    /**
     * @dev Check if buyer has purchased from seller
     */
    function buyerHasPurchased(address buyer, address seller) internal view returns (bool) {
        for (uint256 i = 0; i < buyerOrders[buyer].length; i++) {
            uint256 orderId = buyerOrders[buyer][i];
            if (products[orders[orderId].productId].seller == seller) {
                OrderStatus status = orders[orderId].status;
                if (status == OrderStatus.Delivered || status == OrderStatus.Completed) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @dev Get products by seller
     * @param seller Seller address
     * @return productIds Array of product IDs
     */
    function getSellerProducts(address seller) public view returns (uint256[] memory) {
        return sellerProducts[seller];
    }

    /**
     * @dev Get buyer orders
     * @param buyer Buyer address
     * @return orderIds Array of order IDs
     */
    function getBuyerOrders(address buyer) public view returns (uint256[] memory) {
        return buyerOrders[buyer];
    }

    /**
     * @dev Verify seller (admin)
     * @param seller Seller address
     */
    function verifySeller(address seller) public onlyOwner {
        sellers[seller].verified = true;
    }

    /**
     * @dev Emergency withdraw (owner)
     */
    function emergencyWithdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}