// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// Test double for the pqcVerify precompile (0x...0A01), installed with hardhat_setCode.
/// It is an "oracle": the test harness signs with real ML-DSA-87, checks the signature with
/// the real algorithm off chain, and only then registers that exact (pk, sig, message)
/// triple here. Any triple it was not told about verifies as false, as on the real chain.
contract MockPQCVerify {
    mapping(bytes32 => bool) public valid;

    function register(bytes32 h) external {
        valid[h] = true;
    }

    function pqcVerify(bytes calldata pk, bytes calldata sig, bytes calldata m) external view returns (bool) {
        return valid[keccak256(abi.encode(pk, sig, m))];
    }
}

/// Test double for the pqcKeyStatus precompile (0x...0A02).
contract MockPQCKeyStatus {
    struct S {
        bool registered;
        uint8 alg;
        bytes pk;
        bool pop;
    }
    mapping(address => S) internal s;

    function set(address a, bool registered, uint8 alg, bytes calldata pk, bool pop) external {
        s[a] = S(registered, alg, pk, pop);
    }

    function pqcKeyStatus(address a) external view returns (bool, uint8, bytes memory, bool) {
        S storage x = s[a];
        return (x.registered, x.alg, x.pk, x.pop);
    }
}

/// Minimal ERC-20 for tests.
contract TestToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// A withdrawal recipient that tries to call back into the vault while being paid.
contract Reenterer {
    address public vault;
    uint256 public itemId;

    function arm(address v, uint256 id) external {
        vault = v;
        itemId = id;
    }

    receive() external payable {
        if (vault != address(0)) {
            (bool ok,) = vault.call(abi.encodeWithSignature("execute(uint256)", itemId));
            require(ok, "reentry blocked");
        }
    }
}

/// A pqcVerify stand-in that answers 2 (not a valid ABI bool).
contract GarbageVerify {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(uint256(2));
    }
}

/// A pqcVerify stand-in that answers `true` but with 64 bytes of return data.
contract LongTrueVerify {
    fallback(bytes calldata) external returns (bytes memory) {
        return abi.encode(true, true);
    }
}

/// An ERC-20 whose transfer returns false instead of reverting.
contract FalseToken {
    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

/// An ERC-20 whose transfer returns nothing (USDT-style).
contract NoReturnToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
