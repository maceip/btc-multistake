"use client"


import { useCallback, useContext, useEffect, useState } from "react"
import Image from 'next/image'

import Link from "next/link"
import UniswapV2Factory from "@uniswap/v2-periphery/build/IUniswapV2Router02.json"
import Quoter from "@uniswap/v3-periphery/artifacts/contracts/lens/Quoter.sol/Quoter.json"
import { getExplorers } from "@zetachain/networks"
import { getEndpoints } from "@zetachain/networks/dist/src/getEndpoints"
import { getNetworkName } from "@zetachain/networks/dist/src/getNetworkName"
import networks from "@zetachain/networks/dist/src/networks"
import { getAddress, getNonZetaAddress } from "@zetachain/protocol-contracts"
import { ethers } from "ethers"
import { createMultisigFromCompressedSecp256k1Pubkeys } from "../../lib/multisig"
import wif from 'wif'
import { TBTC,  BitcoinAddressConverter, BitcoinNetwork, Hex, BitcoinPublicKeyUtils, BitcoinPrivateKeyUtils} from "@keep-network/tbtc-v2.ts"
import {
  createMultisigThresholdPubkey,
  isMultisigThresholdPubkey,
  MultisigThresholdPubkey,
  pubkeyToAddress,
} from "@cosmjs/amino";
 import { toHex } from "@cosmjs/encoding"
import { Account } from "@cosmjs/stargate";
import { Buff, Bytes }  from '@cmdcode/buff'
import { MusigContext } from '@cmdcode/musig2'
import * as musig from '@cmdcode/musig2'
import {
  get_ctx,
  hexify,
keys,
musign,
combine_psigs,
verify_musig
} from '@cmdcode/musig2'
import { DirectSecp256k1HdWallet, DirectSecp256k1HdWalletOptions } from "@cosmjs/proto-signing";
import { SigningStargateClient, StargateClient } from "@cosmjs/stargate";

import { formatEther, parseEther } from "ethers/lib/utils"
import { AlertCircle, BookOpen, Check, Loader2, Send, Gift, Bitcoin, Orbit } from "lucide-react"
import { useDebounce } from "use-debounce"
import {
  useContractWrite,
  useNetwork,
  usePrepareContractWrite,
  useWaitForTransaction,
} from "wagmi"

import { useEthersSigner } from "@/lib/ethers"
import { cn } from "@/lib/utils"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { AppContext } from "@/app/index"
import { AccountData, encodeSecp256k1Pubkey } from "@cosmjs/amino"

const emptyPubKeyGroup = () => {
  return { address: "", compressedPubkey: "", keyError: "", isPubkey: false };
};

const contracts: any = {
  goerli_testnet: "0x122F9Cca5121F23b74333D5FBd0c5D9B413bc002",
  mumbai_testnet: "0x392bBEC0537D48640306D36525C64442E98FA780",
  bsc_testnet: "0xc5d7437DE3A8b18f6380f3B8884532206272D599",
}

const MessagingPage = () => {
  const [message, setMessage] = useState("")
  const [multiIBC, setMultiIBC] = useState<any>("")
  const [multiBTC, setMultiBTC] = useState<any>("")


  const [aliceIBC, setAliceIBC] = useState<AccountData>()
  const [bobIBC, setBobIBC] = useState<AccountData>()


  const [destinationNetwork, setDestinationNetwork] = useState("")
  const [destinationChainID, setDestinationChainID] = useState(null)
  const [isZeta, setIsZeta] = useState(false)
  const [currentNetworkName, setCurrentNetworkName] = useState<any>("")
  const [completed, setCompleted] = useState(false)
  const [fee, setFee] = useState("")
  const [currentChain, setCurrentChain] = useState<any>()
    const [pubkeys, setPubkeys] = useState([emptyPubKeyGroup(), emptyPubKeyGroup()]);

  const [debouncedMessage] = useDebounce(message, 500)

  const allNetworks = Object.keys(contracts)
  const signer = useEthersSigner()

  
  const { chain } = useNetwork()
  useEffect(() => {
    setCurrentNetworkName(chain ? getNetworkName(chain.network) : undefined)
    if (chain) {
      setCurrentChain(chain)
      setIsZeta(getNetworkName(chain.network) === "zeta_testnet")
    }
  }, [chain])

  useEffect(() => {
    setDestinationChainID(
      (networks as any)[destinationNetwork]?.chain_id ?? null
    )
  }, [destinationNetwork])
  const { inbounds, setInbounds, fees, bitcoinAddress } = useContext(AppContext)

  const {
    config,
    error: prepareError,
    isError: isPrepareError,
  } = usePrepareContractWrite({
    address: contracts[currentNetworkName || ""],
    abi: [
      {
        inputs: [
          {
            internalType: "uint256",
            name: "destinationChainId",
            type: "uint256",
          },
          {
            internalType: "string",
            name: "message",
            type: "string",
          },
        ],
        name: "sendMessage",
        outputs: [],
        stateMutability: "payable",
        type: "function",
      },
    ],
    value: BigInt(parseFloat(fee) * 1e18 || 0),
    functionName: "sendMessage",
    args: [
      BigInt(destinationChainID !== null ? destinationChainID : 0),
      debouncedMessage,
    ],
  })

  const { data, write } = useContractWrite(config)

  const { isLoading, isSuccess } = useWaitForTransaction({
    hash: data?.hash,
  })

  const sdk = async() => {
   return await TBTC.initializeSepolia(signer!)
  }
  const convertZETAtoMATIC = async (amount: string) => {
    const quoterContract = new ethers.Contract(
      "0xb27308f9F90D607463bb33eA1BeBb41C27CE5AB6",
      Quoter.abi,
      signer
    )
    const quotedAmountOut =
      await quoterContract.callStatic.quoteExactInputSingle(
        "0x0000c9ec4042283e8139c74f4c64bcd1e0b9b54f", // WZETA
        "0x9c3C9283D3e44854697Cd22D3Faa240Cfb032889", // WMATIC
        500,
        parseEther(amount),
        0
      )
    return quotedAmountOut
  }

  const getCCMFee = useCallback(async () => {
    try {
      if (!currentNetworkName || !destinationNetwork) {
        throw new Error("Network is not selected")
      }
      const feeZETA = fees.feesCCM[destinationNetwork].totalFee
      let fee
      if (currentNetworkName === "mumbai_testnet") {
        fee = await convertZETAtoMATIC(feeZETA)
      } else {
        const rpc = getEndpoints("evm", currentNetworkName)[0]?.url
        const provider = new ethers.providers.JsonRpcProvider(rpc)
        const routerAddress = getNonZetaAddress(
          "uniswapV2Router02",
          currentNetworkName
        )
        const router = new ethers.Contract(
          routerAddress,
          UniswapV2Factory.abi,
          provider
        )
        const amountIn = ethers.utils.parseEther(feeZETA)
        const zetaToken = getAddress("zetaToken", currentNetworkName)
        const weth = getNonZetaAddress("weth9", currentNetworkName)
        let zetaOut = await router.getAmountsOut(amountIn, [zetaToken, weth])
        fee = zetaOut[1]
      }
      fee = Math.ceil(parseFloat(formatEther(fee)) * 1.01 * 100) / 100 // 1.01 is to ensure that the fee is enough
      setFee(fee.toString())
    } catch (error) {
      console.error(error)
    }
  }, [currentNetworkName, destinationNetwork])

  useEffect(() => {
    try {
      getCCMFee()
    } catch (error) {
      console.error(error)
    }
  }, [currentNetworkName, destinationNetwork, signer])

  const explorer =
    destinationNetwork &&
    getExplorers(
      contracts[destinationNetwork],
      "address",
      destinationNetwork
    )[0]

  useEffect(() => {
    if (isSuccess && data) {
      const inbound = {
        inboundHash: data.hash,
        desc: `Message sent to ${destinationNetwork}`,
      }
      setCompleted(true)
      setInbounds([inbound, ...inbounds])
    }
  }, [isSuccess, data])

  useEffect(() => {
    setCompleted(false)
  }, [destinationNetwork, message])

  const availableNetworks = allNetworks.filter(
    (network) => network !== currentNetworkName
  )

  function extractDomain(url: string): string | null {
    try {
      const parsedURL = new URL(url)
      const parts = parsedURL.hostname.split(".")
      if (parts.length < 2) {
        return null
      }
      return parts[parts.length - 2]
    } catch (error) {
      console.error("Invalid URL provided:", error)
      return null
    }
  }
  const testbbn = "bbn148lhhfajn9z2hu47vnuchwt07kquky5cqucanl";


  const signers = [ 'me', 'alice', 'bob' ]
  const wallets : any[] = []
  const tweak1  = Buff.random(32)
  const tweak2  = Buff.random(32)
  const options = { key_tweaks : [ tweak1, tweak2 ] }


  for (const name of signers) {
    // Generate some random secrets using WebCrypto.
    const secret = Buff.random(32)
    const nonce  = Buff.random(64)
    // Create a pair of signing keys.
    const [ sec_key, pub_key     ] = keys.get_keypair(secret)

    // Create a pair of nonces (numbers only used once).
    const [ sec_nonce, pub_nonce ] = keys.get_nonce_pair(nonce)
    // Add the member's wallet to the array.
    wallets.push({
      name, sec_key, pub_key, sec_nonce, pub_nonce
    })
  }

  let alicezx = wallets[0].sec_key.hex
  let bobzx = wallets[1].sec_key.hex

  console.log("multisig output zx: ", alicezx);

  console.log("multisig output zx: sub: ", alicezx.substring(1));
const alicepk =  Buffer.from(alicezx, 'hex');
const bobpk =  Buffer.from(bobzx, 'hex');

var alice_key = wif.encode(239, alicepk, true)
var bob_key = wif.encode(239, bobpk, true)

const alice_keypair = BitcoinPrivateKeyUtils.createKeyPair(alice_key, BitcoinNetwork.Testnet);
const bob_keypair = BitcoinPrivateKeyUtils.createKeyPair(bob_key, BitcoinNetwork.Testnet);

  console.log("multisig output: ", alice_keypair.publicKey);

  const mnemonic_alice = "surround miss nominee dream gap cross assault thank captain prosper drop duty group candy wealth weather scale put";
  const mnemonic_bob = "only stone office lady rebel convince layer omit valley trigger slam else avocado sweet noodle excuse display dove";

  
  const bbnOptions: Partial<DirectSecp256k1HdWalletOptions> = {prefix: "bbn"};

  const generate_btc_multi = async (myBtc:string, aliceBtc:string, bobBtc:string) => {
    const encoder = new TextEncoder()
    const tx_message = encoder.encode("{babylon staking txn")
    const group_keys   = wallets.map(e => e.pub_key)
    const group_nonces = wallets.map(e => e.pub_nonce)
    const ctx = get_ctx(group_keys, group_nonces, tx_message, options)
  
    const group_sigs = wallets.map(wallet => {
      return musign(
        ctx,
        wallet.sec_key,
        wallet.sec_nonce
      )
    })
    setMultiBTC(ctx.group_pubkey)
  }

  const generate_ibc_multi = async (testbbn:string, aliceIbc:string, bobInc:string) => {
    let multisigAddress;
    //let compressedPubkeys = [{ address:  aliceIBC?.address!, compressedPubkey:  toHex(aliceIBC?.pubkey!) , keyError: "", isPubkey: false }, { address:  bobIBC?.address, compressedPubkey: toHex(bobIBC?.pubkey!), keyError: "", isPubkey: false }]

   let compressedPubkeys = [{ address:  aliceIBC?.address!, compressedPubkey:  encodeSecp256k1Pubkey(aliceIBC?.pubkey!).value , keyError: "", isPubkey: true }, { address:  bobIBC?.address, compressedPubkey: encodeSecp256k1Pubkey(bobIBC?.pubkey!).value, keyError: "", isPubkey: true }]
   //,{ address:  aliceIBC?.address!, compressedPubkey:  toHex(aliceIBC?.pubkey!) , keyError: "", isPubkey: true }, { address:  bobIBC?.address, compressedPubkey: toHex(bobIBC?.pubkey!), keyError: "", isPubkey: true },{ address:  aliceIBC?.address!, compressedPubkey:  toHex(aliceIBC?.pubkey!) , keyError: "", isPubkey: true }]
/*     compressedPubkeys[0].address = aliceIBC?.address!
    compressedPubkeys[0].compressedPubkey = toHex(aliceIBC?.pubkey!)

    compressedPubkeys[1].address = bobIBC?.address!
   compressedPubkeys[1].compressedPubkey = toHex(bobIBC?.pubkey!) */
   
const keys = compressedPubkeys.map((item) => item.compressedPubkey);
   
      multisigAddress = await createMultisigFromCompressedSecp256k1Pubkeys(
keys,
        2,
        "bbn",
        "bbn-test3",
      );

      
        setMultiIBC(keys)
  }
  

  const init_babylon = async () => {
    const babylon_wallet_alice = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic_alice,bbnOptions);
    const babylon_wallet_bob = await DirectSecp256k1HdWallet.fromMnemonic(mnemonic_bob,bbnOptions);
    const [alice_firstAccount] = await babylon_wallet_alice.getAccounts();
    const [bob_firstAccount] = await babylon_wallet_bob.getAccounts();

    setAliceIBC(alice_firstAccount);
    setBobIBC(bob_firstAccount);
    //const rpcEndpoint = "https://rpc.testnet3.babylonchain.io:443";
    //const alice_client = await SigningStargateClient.connectWithSigner(rpcEndpoint, babylon_wallet_alice);
    //const bob_client = await SigningStargateClient.connectWithSigner(rpcEndpoint, babylon_wallet_bob);


  }
 
  return (
    
    <div className="px-4">
      <h1 className="text-2xl font-bold leading-tight tracking-tight mt-6 mb-4">
        Create Multiparty Bitcoin Stake
      </h1>
      <div className="grid grid-cols-1 sm:grid-cols-6 gap-10 items-start">
        
        <div className="col-span-1 sm:col-span-2">
          
        <Button
                    onClick={async () => {await init_babylon()}}
                    variant="outline"
                    className="w-full rounded-lg"
                  >
                    <Gift className="w-4 h-4 mr-1" />
Connect Babylon IBC 
                 </Button>
          <Card className="p-4">
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault()
                write?.()
              }}
            >

              <div>
                <Label>
                  Your Bitcoin address:
                  </Label>
                
              <Input
              disabled
              value={bitcoinAddress || "Not connected"}
              />
              </div>
            
              {isZeta && (
                <Alert variant="destructive" className="text-sm">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    The protocol currently does not support sending cross-chain
                    messages to/from ZetaChain. Please, switch to another
                    network.
                  </AlertDescription>
                </Alert>
              )}
              <Select
                onValueChange={(e) => setDestinationNetwork(e)}
                disabled={isZeta}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Destination network" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    {availableNetworks.map((network) => (
                      <SelectItem key={network} value={network}>
                        {network}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
              
              <Input
                placeholder="Message"
                disabled={isZeta}
                onChange={(e) => setMessage(e.target.value)}
              />
              <div>
                <Label>
                  Alice's Bitcoin Account
                </Label>
                <Input
                  id="alice_account"
                  placeholder="account"
                  value={BitcoinAddressConverter.publicKeyToAddress( Hex.from(alice_keypair.publicKey),BitcoinNetwork.Testnet,false)}
                />
              </div>
              <div>
                <Label>
                  Bobs's Bitcoin Account
                </Label>
                <Input
                  id="alice_account"
                  placeholder="account"
                  value={BitcoinAddressConverter.publicKeyToAddress( Hex.from(bob_keypair.publicKey),BitcoinNetwork.Testnet,false)}
                />
              </div>
              <div>
                <Label>
                  Your Babylon address:
                  </Label>
                
              <Input
              disabled
              value={testbbn}
              />
              </div>
              <div>
                <Label>
                  Alice's Babylon address:
                  </Label>
                
              <Input
              disabled
              value={aliceIBC?.address || "connecting"}
              />
              </div>
              <div>
                <Label>
                  Bobs's Babylon address:
                  </Label>
                
              <Input
              disabled
              value={bobIBC?.address || "connecting"}
              />
              </div>
              <Input
                hidden 
                disabled         
                value={currentNetworkName || "Please, connect wallet"}
              />
              <div className="rid grid-cols-2 gap-2">
                <div>
              <Button
                                  onClick={async () => {await generate_btc_multi(bitcoinAddress, BitcoinAddressConverter.publicKeyToAddress( Hex.from(bob_keypair.publicKey),BitcoinNetwork.Testnet,false), BitcoinAddressConverter.publicKeyToAddress( Hex.from(alice_keypair.publicKey),BitcoinNetwork.Testnet,false))}}

                type="button"
                variant="outline"
                disabled={
                  isZeta ||
                  isLoading ||
                  !message ||
                  !currentNetworkName
                }
              >
                {isLoading ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Bitcoin className="mr-2 h-4 w-4" />
                )}
                Generate BTC Multisig
              </Button>
              </div>
              <div>
              <Button
                    onClick={async () => {await generate_ibc_multi(testbbn, aliceIBC?.address!, bobIBC?.address! )}}
                    type="button"
                variant="outline"
                disabled={
                  isZeta ||
                  isLoading ||
                  !message ||
                  !currentNetworkName
                }
              >
                {isLoading ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <Orbit className="mr-2 h-4 w-4" />
                )}
Generate IBC Multisig 
             </Button>
             </div>
             </div>
            </form>
            <div
        style={{
          display: "flex",
          justifyContent: "center",
        }}
      >
                      <Image
        src="/b.png"
        width={154}
        height={92}
        alt="babylon logo"
        /> 
        </div>
          </Card>
        </div>

   
        <div className="text-sm col-span-1 sm:col-span-3">
        <Image
        src="/top.png"
        width={1110}
        height={98}
        alt="babylon logo"
        /> 
          <div className="max-w-prose leading-6 space-y-2">


            <p>
              This is a dapp that uses ZetaChain&apos;s{" "}
              <strong>cross-chain messaging</strong>to demonstrate how users
              can create a multiparty staking pool on the babylon network.
              between smart contracts deployed on different chains. It is a
              simple example of how to use the cross-chain messaging to send
              arbitrary data.
            </p>

            <p>
              You can learn how to build a dapp like this by following the
              tutorial:
            </p>
            <Link
              href="https://www.zetachain.com/docs/developers/cross-chain-messaging/examples/hello-world/"
              target="_blank"
            >

              <Button variant="outline" className="mt-4 mb-2">
                <BookOpen className="w-4 h-4 mr-2" />
                Babylon Chain
              </Button>
            </Link>

          </div>

          <div className="max-w-prose leading-6 space-y-2">
            <p>Let&apos;s try using the dapp:</p>
          </div>{" "}
          <ol className="mt-5 text-sm leading-6 space-y-4">
            <li className="flex">
              <Checkbox
                className="mr-2 mt-1"
                disabled
                checked={!!destinationNetwork}
              />
              <span className={cn(!!destinationNetwork && "line-through")}>
                First, select the destination network
              </span>
            </li>
            {!!destinationNetwork && (
              <li className="leading-6">
                <Alert>
                  You&apos;ve selected <strong>{destinationNetwork}</strong> as
                  the destination network.
                </Alert>
              </li>
            )}
            <li className="flex">
              <Checkbox className="mr-2 mt-1" disabled checked={!!message} />
              <span className={cn(!!message && "line-through")}>
                Next, write a message in the input field
              </span>
            </li>
            <li className="flex">
              <Checkbox className="mr-2 mt-1" disabled checked={completed} />
              <span className={cn(completed && "line-through")}>
               Click Generate BTC Multisig
              </span>
            </li>
            <pre className="my-4 rounded-md bg-slate-950 p-4 w-full overflow-x-scroll">
            <code className="text-white">
            {JSON.stringify( {multiBTC})}
            </code>
          </pre>
            <li className="flex">
              <Checkbox className="mr-2 mt-1" disabled checked={completed} />
              <span className={cn(completed && "line-through")}>
                Finally, click Generate IBC Multisig
              </span>
            </li>
            <pre className="my-4 rounded-md bg-slate-950 p-4 w-full overflow-x-scroll">
            <code className="text-white">
            {JSON.stringify( {multiIBC})}
            </code>
          </pre>
            {completed && (
              <li className="leading-6">
                <Alert>
                  Great! You&apos;ve sent a message from {currentNetworkName} to{" "}
                  {destinationNetwork}. Once the cross-chain transaction with
                  the message is processed you will be able to see it in the 
                  <strong>Events</strong> tab in 
                  <a
                    href={explorer}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium text-primary underline underline-offset-4"
                  >
                    {extractDomain(explorer)}
                  </a>
                  .
                </Alert>
              </li>
            )}
          </ol>
        </div>
      </div>
    </div>
  )
}

export default MessagingPage
