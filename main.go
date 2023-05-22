package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/params"
)

var (
	ctx         = context.Background()
	url         = "http://127.0.0.1:7545"
	client, err = ethclient.DialContext(ctx, url)
)

func currentBlock() {
	block, err := client.BlockByNumber(ctx, nil)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(block.Number())
}

func convertWeiToEth(balance *big.Int) *big.Int {
	return new(big.Int).Div(balance, big.NewInt(params.Ether))
}
func convertEtherToWei(ethAmount float64) *big.Int {
	return new(big.Int).Mul(big.NewInt(int64(ethAmount)), big.NewInt(params.Ether))
}

func getWalletBalance() {
	address := common.HexToAddress("0xc48102cdda55b458D357A750Aab910445347FD0c")
	balance, err := client.BalanceAt(ctx, address, nil)
	if err != nil {
		log.Println(err)
		return
	}
	ethbalance := convertWeiToEth(balance)
	fmt.Println(address, balance, params.Ether, ethbalance)
}

func createWallet() (publicAddress string, privateKey string) {
	getPrivatekey, err := crypto.GenerateKey()
	if err != nil {
		log.Println(err)
		return
	}
	getPublickey := crypto.FromECDSA(getPrivatekey)
	thePrivatekey := hexutil.Encode(getPublickey)
	thePublicAddress := crypto.PubkeyToAddress(getPrivatekey.PublicKey).Hex()
	return thePublicAddress, thePrivatekey
}

func sendToWallet() {
	recipientAddress := common.HexToAddress("0x0fC902F8070161523D9AB1c0AfD400DF1E57306B")

	// Get privateKey from publicKey
	privatekey := crypto.ToECDSAUnsafe(common.FromHex("aa330244866065b6a97188ba351583727e41ebd6649f482d4f575a38986712cd"))

	// Get publicKey from privateKey
	publicKey := privatekey.Public()
	publickeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("Public Key Error")
	}

	// Get sender address from publicKey
	senderAddress := crypto.PubkeyToAddress(*publickeyECDSA)
	fmt.Println(recipientAddress, senderAddress, privatekey)
	nonce, err := client.PendingNonceAt(ctx, senderAddress)
	if err != nil {
		log.Println(err)
		return
	}
	amount := convertEtherToWei(1)
	gasLimit := 21000
	gas, err := client.SuggestGasPrice(ctx)
	if err != nil {
		log.Println(err)
		return
	}
	networkID, err := client.NetworkID(ctx)
	if err != nil {
		log.Println(err)
		return
	}
	transaction := types.NewTransaction(nonce, recipientAddress, amount, uint64(gasLimit), gas, nil)
	signedTx, err := types.SignTx(transaction, types.NewEIP155Signer(networkID), privatekey)
	if err != nil {
		log.Println(err)
		return
	}
	err = client.SendTransaction(ctx, signedTx)
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Printf("transaction sent: %s", signedTx.Hash().Hex())
}

func GetTransaction(hash string) {
	tx, pending, err := client.TransactionByHash(ctx, common.HexToHash(hash))
	if err != nil {
		log.Println(err)
		return
	}
	fmt.Println(tx.Value(), tx.To(), pending)
}

func main() {
	currentBlock()
	getWalletBalance()
	// pubAddr, pubKey := createWallet()
	// fmt.Println("wallet info:", pubAddr, pubKey)
	sendToWallet()
	// GetTransaction("0xbb3dcb1a862423ddc766bf6008f6a86b1b726d7376ee1591a0adfb8cf0316f97")
}
