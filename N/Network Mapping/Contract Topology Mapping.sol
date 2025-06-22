contract TopologyMapper {
    struct Link {
        address parent;
        address child;
    }

    Link[] public links;

    function registerLink(address parent, address child) external {
        links.push(Link(parent, child));
    }

    function getAll() external view returns (Link[] memory) {
        return links;
    }
}
