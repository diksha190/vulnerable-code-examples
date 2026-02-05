// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title DeFiLendingPool
 * @notice A decentralized lending pool with collateralized loans
 * @dev This contract has several subtle security vulnerabilities for testing
 */

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
    function updatePrice(address token, uint256 price) external;
}

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

contract DeFiLendingPool {
    
    // Constants
    uint256 public constant LIQUIDATION_THRESHOLD = 150; // 150% collateralization
    uint256 public constant LIQUIDATION_BONUS = 10; // 10% bonus for liquidators
    uint256 public constant INTEREST_RATE = 5; // 5% annual interest
    uint256 public constant PRECISION = 1e18;
    
    // State variables
    address public owner;
    IPriceOracle public priceOracle;
    address public governanceToken;
    
    // Supported tokens
    mapping(address => bool) public supportedTokens;
    mapping(address => uint256) public totalDeposits;
    mapping(address => uint256) public totalBorrows;
    
    // User positions
    struct Position {
        uint256 collateralAmount;
        uint256 borrowAmount;
        uint256 lastUpdateTime;
        address collateralToken;
        address borrowToken;
    }
    
    mapping(address => Position) public positions;
    mapping(address => uint256) public rewards;
    
    // Events
    event Deposited(address indexed user, address indexed token, uint256 amount);
    event Borrowed(address indexed user, address indexed token, uint256 amount);
    event Repaid(address indexed user, uint256 amount);
    event Liquidated(address indexed user, address indexed liquidator, uint256 amount);
    event RewardsClaimed(address indexed user, uint256 amount);
    
    // Modifiers
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    modifier validToken(address token) {
        require(supportedTokens[token], "Token not supported");
        _;
    }
    
    constructor(address _priceOracle, address _governanceToken) {
        owner = msg.sender;
        priceOracle = IPriceOracle(_priceOracle);
        governanceToken = _governanceToken;
    }
    
    /**
     * @notice Deposit collateral into the lending pool
     * @param token The token to deposit
     * @param amount The amount to deposit
     */
    function deposit(address token, uint256 amount) external validToken(token) {
        require(amount > 0, "Amount must be greater than 0");
        
        IERC20(token).transferFrom(msg.sender, address(this), amount);
        
        Position storage position = positions[msg.sender];
        position.collateralAmount += amount;
        position.collateralToken = token;
        position.lastUpdateTime = block.timestamp;
        
        totalDeposits[token] += amount;
        
        // VULNERABILITY 1: No reentrancy guard on deposit
        // An attacker could exploit this with a malicious token
        
        emit Deposited(msg.sender, token, amount);
    }
    
    /**
     * @notice Borrow tokens against collateral
     * @param borrowToken The token to borrow
     * @param amount The amount to borrow
     */
    function borrow(address borrowToken, uint256 amount) external validToken(borrowToken) {
        Position storage position = positions[msg.sender];
        require(position.collateralAmount > 0, "No collateral");
        
        // Calculate borrowing power
        uint256 collateralValue = _getCollateralValue(msg.sender);
        uint256 currentDebt = _getCurrentDebt(msg.sender);
        uint256 maxBorrow = (collateralValue * 100) / LIQUIDATION_THRESHOLD;
        
        require(currentDebt + amount <= maxBorrow, "Insufficient collateral");
        
        position.borrowAmount += amount;
        position.borrowToken = borrowToken;
        totalBorrows[borrowToken] += amount;
        
        // VULNERABILITY 2: No slippage protection
        // Price could change between check and transfer
        IERC20(borrowToken).transfer(msg.sender, amount);
        
        emit Borrowed(msg.sender, borrowToken, amount);
    }
    
    /**
     * @notice Repay borrowed tokens
     * @param amount The amount to repay
     */
    function repay(uint256 amount) external {
        Position storage position = positions[msg.sender];
        require(position.borrowAmount > 0, "No debt");
        
        uint256 debt = _getCurrentDebt(msg.sender);
        require(amount <= debt, "Amount exceeds debt");
        
        IERC20(position.borrowToken).transferFrom(msg.sender, address(this), amount);
        
        position.borrowAmount -= amount;
        totalBorrows[position.borrowToken] -= amount;
        
        // Update interest
        position.lastUpdateTime = block.timestamp;
        
        emit Repaid(msg.sender, amount);
    }
    
    /**
     * @notice Liquidate an undercollateralized position
     * @param user The user to liquidate
     */
    function liquidate(address user) external {
        Position storage position = positions[user];
        require(position.borrowAmount > 0, "No position to liquidate");
        
        // Check if position is undercollateralized
        uint256 collateralValue = _getCollateralValue(user);
        uint256 debtValue = _getDebtValue(user);
        
        require(
            collateralValue * 100 < debtValue * LIQUIDATION_THRESHOLD,
            "Position is healthy"
        );
        
        // Calculate liquidation bonus
        uint256 liquidationAmount = position.borrowAmount;
        uint256 bonusAmount = (liquidationAmount * LIQUIDATION_BONUS) / 100;
        
        // VULNERABILITY 3: Reentrancy in liquidation
        // External call before state update
        IERC20(position.collateralToken).transfer(
            msg.sender,
            position.collateralAmount + bonusAmount
        );
        
        // State update after external call (VULNERABLE!)
        position.collateralAmount = 0;
        position.borrowAmount = 0;
        
        emit Liquidated(user, msg.sender, liquidationAmount);
    }
    
    /**
     * @notice Calculate accrued interest for a position
     * @param user The user address
     * @return The total debt including interest
     */
    function _getCurrentDebt(address user) internal view returns (uint256) {
        Position memory position = positions[user];
        if (position.borrowAmount == 0) return 0;
        
        uint256 timeElapsed = block.timestamp - position.lastUpdateTime;
        
        // VULNERABILITY 4: Integer division precision loss
        // This can lead to rounding errors that benefit borrowers
        uint256 interest = (position.borrowAmount * INTEREST_RATE * timeElapsed) / (365 days * 100);
        
        return position.borrowAmount + interest;
    }
    
    /**
     * @notice Get the USD value of user's collateral
     * @param user The user address
     * @return The collateral value in USD
     */
    function _getCollateralValue(address user) internal view returns (uint256) {
        Position memory position = positions[user];
        
        // VULNERABILITY 5: Oracle manipulation vulnerability
        // Single price source without validation or TWAP
        uint256 price = priceOracle.getPrice(position.collateralToken);
        
        return (position.collateralAmount * price) / PRECISION;
    }
    
    /**
     * @notice Get the USD value of user's debt
     * @param user The user address
     * @return The debt value in USD
     */
    function _getDebtValue(address user) internal view returns (uint256) {
        Position memory position = positions[user];
        uint256 debt = _getCurrentDebt(user);
        
        uint256 price = priceOracle.getPrice(position.borrowToken);
        return (debt * price) / PRECISION;
    }
    
    /**
     * @notice Claim accumulated rewards
     */
    function claimRewards() external {
        uint256 reward = rewards[msg.sender];
        require(reward > 0, "No rewards");
        
        rewards[msg.sender] = 0;
        
        // VULNERABILITY 6: No checks-effects-interactions pattern
        IERC20(governanceToken).transfer(msg.sender, reward);
        
        emit RewardsClaimed(msg.sender, reward);
    }
    
    /**
     * @notice Update the price oracle address
     * @param newOracle The new oracle address
     */
    function updateOracle(address newOracle) external {
        // VULNERABILITY 7: Missing access control!
        // Anyone can change the oracle
        priceOracle = IPriceOracle(newOracle);
    }
    
    /**
     * @notice Add a supported token
     * @param token The token address
     */
    function addSupportedToken(address token) external onlyOwner {
        supportedTokens[token] = true;
    }
    
    /**
     * @notice Emergency withdraw for owner
     * @param token The token to withdraw
     * @param amount The amount to withdraw
     */
    function emergencyWithdraw(address token, uint256 amount) external onlyOwner {
        // VULNERABILITY 8: No timelock on emergency functions
        // Owner can rug pull immediately
        IERC20(token).transfer(owner, amount);
    }
    
    /**
     * @notice Update user rewards based on their position
     * @param user The user address
     */
    function updateRewards(address user) external {
        Position memory position = positions[user];
        
        // Calculate rewards based on deposit time
        uint256 timeElapsed = block.timestamp - position.lastUpdateTime;
        uint256 reward = (position.collateralAmount * timeElapsed) / (365 days);
        
        // VULNERABILITY 9: Reward calculation vulnerable to manipulation
        // No cap on rewards, can be gamed
        rewards[user] += reward;
    }
    
    /**
     * @notice Get health factor of a position
     * @param user The user address
     * @return The health factor (collateral value / debt value * 100)
     */
    function getHealthFactor(address user) external view returns (uint256) {
        uint256 collateralValue = _getCollateralValue(user);
        uint256 debtValue = _getDebtValue(user);
        
        if (debtValue == 0) return type(uint256).max;
        
        return (collateralValue * 100) / debtValue;
    }
    
    /**
     * @notice Transfer ownership
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Invalid address");
        owner = newOwner;
    }
    
    /**
     * @notice Pause the contract
     */
    function pause() external onlyOwner {
        // VULNERABILITY 10: No pause functionality implemented
        // This function does nothing!
    }
}