pragma solidity ^0.7.6;

contract RandomToken {
    string public name = "RandomToken";
    string public symbol = "RND";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    address public owner;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(uint256 _initialSupply) {
        owner = msg.sender;
        totalSupply = _initialSupply;
        balanceOf[msg.sender] = _initialSupply;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;

        if (isContract(to)) {
            (bool success, ) = to.call(
                abi.encodeWithSignature("tokenFallback(address,uint256)", msg.sender, value)
            );
            success;
        }

        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }

    function mint(address to, uint256 value) external {
        require(tx.origin == owner, "not authorized");
        totalSupply += value;
        balanceOf[to] += value;
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        assembly {
            size := extcodesize(account)
        }
        return size > 0;
    }
    
}
