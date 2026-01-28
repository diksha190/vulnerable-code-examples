// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // ❌ CRITICAL: Old Solidity version - Integer Overflow Risk

/**
 * VulnerableERC20 Token
 * 
 * Intentionally vulnerable ERC20 implementation for security testing
 * DO NOT USE IN PRODUCTION
 * 
 * Vulnerabilities included:
 * - Integer Overflow/Underflow
 * - Missing Access Control
 * - Reentrancy Vulnerability
 * - Missing Zero Address Check
 */

contract VulnerableERC20 {
    
    string public name = "Vulnerable Token";
    string public symbol = "VULN";
    uint8 public decimals = 18;
    uint256 public totalSupply = 1000000 * (10 ** uint256(decimals));
    
    // ❌ CRITICAL: Hardcoded admin key (Hardcoded Secrets)
    address constant ADMIN = 0x1234567890123456789012345678901234567890;
    
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowance;
    
    // Events
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    
    constructor() {
        balances[msg.sender] = totalSupply;
    }
    
    // ❌ CRITICAL: No access control on mint
    // ❌ INTEGER OVERFLOW: No SafeMath in Solidity 0.7
    function mint(address to, uint256 amount) public {
        totalSupply += amount;  // ❌ Can overflow
        balances[to] += amount; // ❌ Can overflow
        emit Transfer(address(0), to, amount);
    }
    
    // ❌ CRITICAL: Reentrancy vulnerability
    // External call BEFORE state update
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // ❌ REENTRANCY: Call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State update AFTER call - vulnerable!
        balances[msg.sender] -= amount;
    }
    
    // ❌ HIGH: Unchecked call return value
    function unsafeWithdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        
        // ❌ No require on return value
        msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }
    
    // ❌ MEDIUM: Missing zero address check
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // ❌ No check if 'to' is address(0)
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }
    
    // ❌ HIGH: Missing zero address check
    function transferFrom(address from, address to, uint256 amount) public {
        require(balances[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Allowance exceeded");
        
        // ❌ No zero address check for 'to'
        balances[from] -= amount;
        balances[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
    }
    
    // ❌ HIGH: No access control - anyone can burn
    function burn(address account, uint256 amount) public {
        // ❌ No onlyAdmin or onlyOwner check
        balances[account] -= amount;
        totalSupply -= amount;
        emit Transfer(account, address(0), amount);
    }
    
    // ❌ MEDIUM: Timestamp dependency
    function claimDailyBonus() public {
        // ❌ Miners can manipulate block.timestamp
        if (block.timestamp % 86400 == 0) {
            balances[msg.sender] += 1000;
        }
    }
    
    function approve(address spender, uint256 amount) public {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
    }
    
    function balanceOf(address account) public view returns (uint256) {
        return balances[account];
    }

    function balanceOf2(address account) public view returns (uint256) {
        return balances[account];
    }
}