//geth --datadir "ethdevdata" --dev --rpc --rpcaddr "0.0.0.0" console 2>>file_to_log_output
geth --identity "phoenix"  --rpc  --rpccorsdomain "*" --datadir "/root/ethdevdata"  --dev --rpc --rpcaddr "0.0.0.0" --rpcapi "db,eth,net,web3" --networkid 98888 console 2>>file_to_log_output
//启动另一个终端来作为console
//geth --dev console 2>>file_to_log_output

//查看账号
eth.accounts

创建一个新账户
personal.newAccount('123456')

user1=eth.accounts[0]
user2=eth.accounts[1]
eth.getBalance(user1)
eth.getBalance(user2)

miner.start()
miner.stop()

user1向user2转移以太币
eth.sendTransaction({from: user1,to: user2,value: web3.toWei(3,"ether")})

personal.unlockAccount(user1,'123456')
eth.sendTransaction({from: user1,to: user2,value: web3.toWei(3,"ether")})

智能合约
contract test {  
    function multiply(uint a) returns(uint d) {  
        return a * 7;   
    }   
}  
source = "contract test { function multiply(uint a) returns(uint d) { return a * 7; } }"
contract = eth.compile.solidity(source).test
以上语句报错
用以下方法：

 /////////////////////////////////////////////////////////////
 solc --bin Test.sol
solc --abi Test.sol
abi = JSON.parse('[{"constant":false,"inputs":[{"name":"a","type":"uint256"}],"name":"multiply","outputs":[{"name":"d","type":"uint256"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]')

bytecode = '0x60606040523415600e57600080fd5b60a98061001c6000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063c6888fa114603c57600080fd5b3415604657600080fd5b605a60048080359060200190919050506070565b6040518082815260200191505060405180910390f35b60006007820290509190505600a165627a7a723058205f6f417a1ebd4d6c82f954c8b45fc6a9426b320aff6b40b7c8c6ff1894eb23390029'

 读取abi文件和bin文件

 >contract = eth.contract(abi)
 >deployed = contract.new({from: eth.accounts[0], data: bytecode, gas: 1000000})
deployed就是部署的实例了，contract.new就是部署，接收的参数里from表示用哪个账号去创建，这个账号的地址就会是contractg构造函数里的那个msg.sender，也就是这个合约以后的owner了
personal.unlockAccount(user1,'123456')
deployed.multiply.call(3)
或者
  >c = eth.contract(abi)
  >instance = c.at("0x69a4c171e4ff1e60985b15cdbaa398b94081c699")
首先根据abi文件构造合约接口，然后指向合约部署的地址
>instance.multiply.call(3)
>instance.multiply(3, {from:eth.accounts[0]})
personal.unlockAccount(user1,'123456')

testsol 部署地址0x4a8822c83e2dccec89e8c90c3638145976aaf9df

部署实例后的地址是undefined，因为交易才发送出去，没有矿工挖矿，没有写进区块链，所以还不知道。现在可以用txpool.status查看到，挖矿后console输入deployed可看到address，就是此合约地址


启动挖矿，把交易写进区块链。miner.start()，然后关闭挖矿miner.stop()


挖矿之后，交易就写进区块链了。此时再查看contract就能看见有地址了

/////////////挖矿到某个真实地址/////////////////////////
geth --etherbase 1 --mine  2>> geth.log // 1 is index: second account by creation order OR
geth --etherbase '0xB16FC01EE749d4Db81F712E6747120323eebA8f7' --mine 2>> geth.log

/root/go-ethereum/build/bin/geth --etherbase '0xB16FC01EE749d4Db81F712E6747120323eebA8f7' --mine --minerthreads=4 2>> geth.log


//abigen --abi testsol.abi --pkg main --type Token --out testsol.go
//go:generate abigen --sol testsol.sol --pkg main --out testsol.go
abigen --sol testsol.sol --pkg main --out testsol.go

curl -X POST --data '{"jsonrpc":"2.0","method":"net_version","params":[],"id":67}' http://localhost:8545

curl -X POST --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":67}' http://localhost:8545

curl -X POST --data '{"jsonrpc":"2.0","method":"net_listening","params":[],"id":67}' http://localhost:8545

curl -X POST --data '{"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":73}' http://localhost:8545

curl -X POST --data '{"jsonrpc":"2.0", "method": "eth_getStorageAt", "params": ["0xb13edd24707dfc039614c1c8927f2baafb36474c", "0x0", "latest"], "id": 1}' localhost:8545
testsol 部署地址
address: "0xb13edd24707dfc039614c1c8927f2baafb36474c",
  transactionHash: "0xac99518b20395665dfd9fae531f173e3de1a1466faf434d9cc6650a3228b8ec6"

  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getBlockByHash","params":["0xf60c195debeaecdfc73f62b68a5ba52970378d4c01748db1277e4298615e897e", true],"id":1}' localhost:8545

  web3.eth.blockNumber
  web3.eth.getBlock(3).hash
  web3.eth.getBlock(BLOCK_NUMBER)

  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x3", true],"id":1}' localhost:8545

  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0xf60c195debeaecdfc73f62b68a5ba52970378d4c01748db1277e4298615e897e"],"id":1}' localhost:8545

  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getTransactionByBlockNumberAndIndex","params":["0x5", "0x0"],"id":1}' localhost:8545

  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_getCompilers","params":[],"id":1}' localhost:8545

  curl -X POST --data '{"jsonrpc":"2.0","method":"eth_compileSolidity","params":["contract test { function multiply(uint a) returns(uint d) {   return a * 7;   } }"],"id":1}' localhost:8545