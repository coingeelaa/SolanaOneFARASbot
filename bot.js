require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const QRCode = require('qrcode');
const { Telegraf, Markup, session } = require('telegraf');
const {
  Connection,
  PublicKey,
  Keypair,
  Transaction,
  SystemProgram,
  LAMPORTS_PER_SOL
} = require('@solana/web3.js');
const {
  getOrCreateAssociatedTokenAccount,
  createTransferInstruction,
  TOKEN_PROGRAM_ID
} = require('@solana/spl-token');
const admin = require('firebase-admin');
const bs58 = require('bs58');
const moment = require('moment-timezone');

// ----------------- Environment & Encryption Setup -----------------
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
  console.error('ENCRYPTION_KEY environment variable is not set.');
  process.exit(1);
}
if (Buffer.from(ENCRYPTION_KEY, 'hex').length !== 32) {
  console.error('ENCRYPTION_KEY must be a 32-byte key in hex format.');
  process.exit(1);
}
const ALGORITHM = 'aes-256-cbc';

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  const textParts = encryptedText.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encrypted = textParts.join(':');
  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ----------------- Local Private Keys Storage -----------------
const PRIVATE_KEYS_FILE = path.join(__dirname, 'privateKeys.json');

function loadLocalPrivateKeys() {
  if (!fs.existsSync(PRIVATE_KEYS_FILE)) return {};
  const data = fs.readFileSync(PRIVATE_KEYS_FILE);
  try {
    return JSON.parse(data);
  } catch (error) {
    console.error('Error parsing local private keys file:', error);
    return {};
  }
}

function saveLocalPrivateKeys(keys) {
  fs.writeFileSync(PRIVATE_KEYS_FILE, JSON.stringify(keys, null, 2));
}

function setLocalPrivateKey(walletId, privateKey) {
  const keys = loadLocalPrivateKeys();
  const encryptedKey = encrypt(privateKey);
  keys[walletId] = encryptedKey;
  saveLocalPrivateKeys(keys);
}

function getLocalPrivateKey(walletId) {
  const keys = loadLocalPrivateKeys();
  const encryptedKey = keys[walletId];
  if (!encryptedKey) return null;
  return decrypt(encryptedKey);
}

function removeLocalPrivateKey(walletId) {
  const keys = loadLocalPrivateKeys();
  delete keys[walletId];
  saveLocalPrivateKeys(keys);
}

// ----------------- Helper for Base58 Decoding -----------------
function decodeBase58(str) {
  if (typeof bs58.decode === 'function') return bs58.decode(str);
  if (bs58.default && typeof bs58.default.decode === 'function') return bs58.default.decode(str);
  throw new Error('Base58 decode function not available.');
}

// ----------------- FARASbot MINT Address -----------------
const FARASBOT_MINT = new PublicKey(process.env.FARASBOT_MINT_ADDRESS || "4hZ8iCL6Tz17J84UBaAdhCTeq96k45k6Ety7wBWB9Dra");

// ----------------- Transfer FARASbot Function -----------------
async function transferFARASbot(bonusAmount, userPublicKey) {
  try {
    const decimals = 9;
    const integerAmount = Math.round(bonusAmount * 10 ** decimals);

    const fromTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      botKeypair,
      FARASBOT_MINT,
      botKeypair.publicKey
    );

    const toTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      botKeypair,
      FARASBOT_MINT,
      new PublicKey(userPublicKey)
    );

    const transaction = new Transaction().add(
      createTransferInstruction(
        fromTokenAccount.address,
        toTokenAccount.address,
        botKeypair.publicKey,
        integerAmount,
        [],
        TOKEN_PROGRAM_ID
      )
    );

    const signature = await connection.sendTransaction(transaction, [botKeypair]);
    console.log("✅ FARASbot Transfer successful. Sig:", signature);
    return signature;
  } catch (error) {
    console.error("❌ transferFARASbot Error:", error);
    throw error;
  }
}

// ----------------- Helper Functions -----------------
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Operation timed out after ${ms} ms`));
    }, ms);
    promise.then((res) => {
      clearTimeout(timer);
      resolve(res);
    }).catch((err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ----------------- Firebase Initialization -----------------
const serviceAccount = require("./dssa-58488-firebase-adminsdk-fbsvc-554c55cdb8.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});
const db = admin.firestore();

// ----------------- Solana Connection -----------------
const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');

// ----------------- Global Subscriptions -----------------
const subscriptions = {};

// ----------------- Admin Configuration -----------------
const ADMINS = process.env.ADMINS ? process.env.ADMINS.split(',').map(Number) : [];

// ----------------- Telegram Bot Initialization -----------------
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
bot.use(session());
bot.use((ctx, next) => {
  ctx.session = ctx.session || {};
  return next();
});

// ----------------- BOT Wallet Fallback Using BOT_WALLET_SECRET -----------------
let botKeypair;
try {
  botKeypair = Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(process.env.BOT_WALLET_SECRET))
  );
} catch (error) {
  console.error('Error initializing BOT Keypair:', error);
  process.exit(1);
}

async function botWalletHasSufficientSOL(requiredSol) {
  const balance = await connection.getBalance(botKeypair.publicKey);
  const balanceSOL = balance / LAMPORTS_PER_SOL;
  return balanceSOL >= requiredSol;
}

async function transferFromBotWallet(solAmount, destinationAddress) {
  const toPublicKey = new PublicKey(destinationAddress);
  const lamports = Math.round(solAmount * LAMPORTS_PER_SOL);
  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: botKeypair.publicKey,
      toPubkey: toPublicKey,
      lamports,
    })
  );
  const signature = await connection.sendTransaction(transaction, [botKeypair], { preflightCommitment: 'finalized' });
  console.log("BOT wallet transfer successful, signature:", signature);
  return {
    acquiredSol: solAmount,
    withdrawalFee: 0,
    netSol: solAmount,
    withdrawalId: signature,
  };
}

// ----------------- Referral Logic -----------------
async function registerReferral(userId, referralCode) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists || !userDoc.data().referredBy) {
    await userRef.set({ referredBy: referralCode }, { merge: true });
    console.log(`User ${userId} referred by ${referralCode}`);
  }
}

async function updateReferralBonus(referrerCode, feePaid, transactionData, referredUserId) {
  try {
    const referredUserRef = db.collection('users').doc(referredUserId.toString());
    const referredUserDoc = await referredUserRef.get();
    if (!referredUserDoc.exists) {
      console.log('❌ Referred user not found in DB.');
      return;
    }
    const referredUserData = referredUserDoc.data();
    if (!referredUserData.joinedAt) {
      console.log('❌ Referred user does not have a joinedAt field.');
      return;
    }
    const joinedDate = referredUserData.joinedAt.toDate();
    const now = new Date();
    const yearDiff = now.getFullYear() - joinedDate.getFullYear();
    const monthDiff = (yearDiff * 12) + (now.getMonth() - joinedDate.getMonth());

    let bonusPercentage = 0.05; // default
    if (monthDiff === 0) {
      bonusPercentage = 0.25;
    } else if (monthDiff === 1) {
      bonusPercentage = 0.15;
    }

    const bonusAmount = feePaid * bonusPercentage;

    const bonusDocRef = await db.collection('referralBonuses').add({
      referrerCode,
      referredUserId,
      transactionId: transactionData.withdrawalId || transactionData.signature || 'N/A',
      feePaid,
      bonusPercentage,
      bonusAmount,
      transactionDate: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`✅ Referral bonus of ${bonusAmount} credited to referrer ${referrerCode} (monthDiff=${monthDiff}).`);

    let referrerId = parseInt(referrerCode.replace('ref', ''), 10);
    if (isNaN(referrerId)) {
      referrerId = parseInt(referrerCode, 10);
    }
    if (isNaN(referrerId)) {
      console.log("❌ Could not parse referrerId from code:", referrerCode);
      return;
    }
    const referrerActiveWallet = await getActiveWallet(referrerId);
    if (!referrerActiveWallet) {
      console.log("❌ Referrer has no active wallet. Skipping FARASbot transfer.");
      return;
    }
    const sig = await transferFARASbot(bonusAmount, referrerActiveWallet.publicKey);
    console.log("✅ FARASbot transferred to referrer wallet:", sig);
    await bonusDocRef.update({ farasbotTransferSignature: sig });
  } catch (error) {
    console.error('❌ updateReferralBonus Error:', error);
  }
}

async function getAllReferrals(referralCode, maxDepth = 5) {
  const queue = [{ code: referralCode, level: 0 }];
  const visited = new Set([referralCode]);

  const directRefs = [];
  const indirectRefs = [];

  while (queue.length > 0) {
    const { code: currentCode, level } = queue.shift();
    if (level >= maxDepth) continue;

    const snapshot = await db.collection('users')
      .where('referredBy', '==', currentCode)
      .get();

    for (const doc of snapshot.docs) {
      const data = doc.data();
      if (!data.referralCode) continue;

      if (!visited.has(data.referralCode)) {
        visited.add(data.referralCode);

        if (level === 0) {
          directRefs.push(data);
        } else {
          indirectRefs.push(data);
        }

        queue.push({ code: data.referralCode, level: level + 1 });
      }
    }
  }

  return { directRefs, indirectRefs };
}

async function getUserReferralStatsMultiLevel(userId, botUsername) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists) {
    return {
      code: null,
      link: null,
      directCount: 0,
      indirectCount: 0,
      totalRewards: 0,
      totalPaid: 0,
      totalUnpaid: 0,
    };
  }

  let code = userDoc.data().referralCode;
  if (!code) {
    code = `ref${userId}`;
    await userRef.set({ referralCode: code }, { merge: true });
  }
  const link = `https://t.me/${botUsername}?start=${code}`;

  const { directRefs, indirectRefs } = await getAllReferrals(code, 5);
  const directCount = directRefs.length;
  const indirectCount = indirectRefs.length;

  const snapshot = await db.collection('referralBonuses')
    .where('referrerCode', '==', code)
    .get();

  let totalRewards = 0;
  let totalPaid = 0;
  let totalUnpaid = 0;
  snapshot.forEach(doc => {
    const data = doc.data();
    const amt = data.bonusAmount || 0;
    totalRewards += amt;
    if (data.farasbotTransferSignature) {
      totalPaid += amt;
    } else {
      totalUnpaid += amt;
    }
  });

  return {
    code,
    link,
    directCount,
    indirectCount,
    totalRewards,
    totalPaid,
    totalUnpaid
  };
}

// ----------------- Helper Functions for Solana -----------------
const getSolPrice = async () => {
  try {
    const res = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
    return res.data.solana.usd;
  } catch (error) {
    console.error('❌ SOL Price Error:', error);
    return null;
  }
};

const isValidSolanaAddress = (address) => {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
};

const calculateNetAmount = (amount, feeRate = 0.02) => {
  const fee = amount * feeRate;
  const netAmount = amount - fee;
  return { fee, netAmount };
};

const saveTransaction = async (userId, type, amountSOL, amountUSD, address, txId) => {
  try {
    await db.collection('transactions').add({
      userId: userId.toString(),
      type,
      amountSOL,
      amountUSD,
      address,
      transactionId: txId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log('💾 Transaction saved.');
  } catch (error) {
    console.error('❌ Transaction Save Error:', error);
  }
};

const listenForIncomingTransactions = async (publicKey) => {
  if (subscriptions[publicKey]) {
    console.log(`🔔 Already subscribed for ${publicKey}`);
    return;
  }
  try {
    const subId = connection.onAccountChange(
      new PublicKey(publicKey),
      (accountInfo) => {
        console.log(`🔔 Update for ${publicKey}:`, accountInfo);
      },
      'confirmed'
    );
    subscriptions[publicKey] = subId;
    console.log(`👂 Listening on ${publicKey} (sub ID: ${subId})`);
  } catch (error) {
    console.error('❌ Subscription Error:', error);
  }
};

// ----------------- Wallet Management Functions -----------------
async function getActiveWallet(userId) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists || !userDoc.data().activeWalletId) return null;
  const walletRef = userRef.collection('wallets').doc(userDoc.data().activeWalletId);
  const walletDoc = await walletRef.get();
  return walletDoc.exists ? { id: walletDoc.id, ...walletDoc.data() } : null;
}

async function createNewWallet(userId, phone, firstName, lastName, username, email) {
  const keypair = Keypair.generate();
  const publicKey = keypair.publicKey.toString();
  const privateKeyHex = Buffer.from(keypair.secretKey).toString('hex');

  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();

  if (!userDoc.exists) {
    await userRef.set({
      phone, firstName, lastName, username, email,
      joinedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  } else {
    if (!userDoc.data().joinedAt) {
      await userRef.set({
        joinedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }
    await userRef.set({ phone, firstName, lastName, username, email }, { merge: true });
  }

  const walletData = {
    publicKey,
    type: 'new',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };
  const walletRef = await userRef.collection('wallets').add(walletData);
  await userRef.update({ activeWalletId: walletRef.id });
  await listenForIncomingTransactions(publicKey);

  setLocalPrivateKey(walletRef.id, privateKeyHex);

  return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
}

async function importWalletByPrivateKey(userId, phone, firstName, lastName, username, email, privateKeyInput) {
  try {
    let secretKeyUint8;
    const trimmedKey = privateKeyInput.trim();
    if (trimmedKey.startsWith('[')) {
      secretKeyUint8 = new Uint8Array(JSON.parse(trimmedKey));
    } else if (/^[0-9a-fA-F]+$/.test(trimmedKey)) {
      secretKeyUint8 = Uint8Array.from(Buffer.from(trimmedKey, 'hex'));
    } else {
      secretKeyUint8 = decodeBase58(trimmedKey);
    }

    let keypair;
    try {
      keypair = Keypair.fromSecretKey(secretKeyUint8);
    } catch {
      try {
        keypair = Keypair.fromSeed(secretKeyUint8);
      } catch {
        throw new Error('❌ Invalid private key format.');
      }
    }

    const publicKey = keypair.publicKey.toString();

    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
      await userRef.set({
        phone, firstName, lastName, username, email,
        joinedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    } else {
      if (!userDoc.data().joinedAt) {
        await userRef.set({
          joinedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      }
      await userRef.set({ phone, firstName, lastName, username, email }, { merge: true });
    }

    const walletData = {
      publicKey,
      type: 'import',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    const walletRef = await userRef.collection('wallets').add(walletData);
    await userRef.update({ activeWalletId: walletRef.id });

    await listenForIncomingTransactions(publicKey);
    setLocalPrivateKey(walletRef.id, privateKeyInput);

    return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
  } catch (error) {
    console.error('❌ Wallet Import Error:', error);
    throw error;
  }
}

async function recoverWalletByPhrase(userId, phone, firstName, lastName, username, email, phrase) {
  try {
    return await createNewWallet(userId, phone, firstName, lastName, username, email);
  } catch (error) {
    console.error('❌ Wallet Recovery Error:', error);
    throw error;
  }
}

async function resetWallet(userId) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists) throw new Error('User not found');

  const userData = userDoc.data();
  const phone = userData.phone || 'Not provided';
  const firstName = userData.firstName || 'Not provided';
  const lastName = userData.lastName || 'Not provided';
  const username = userData.username || 'Not provided';
  const email = userData.email || 'Not provided';

  const newWallet = await createNewWallet(userId, phone, firstName, lastName, username, email);

  if (userData.activeWalletId) {
    const oldWalletRef = userRef.collection('wallets').doc(userData.activeWalletId);
    await oldWalletRef.update({ discarded: true, discardedAt: admin.firestore.FieldValue.serverTimestamp() });
    removeLocalPrivateKey(userData.activeWalletId);
  }
  return newWallet;
}

// ----------------- Preauthorization Functions -----------------
async function commitPreauthorization(referenceId, transactionId) {
  const commitBody = {
    schemaVersion: "1.0",
    requestId: Date.now().toString(),
    timestamp: new Date().toISOString(),
    channelName: "WEB",
    serviceName: "API_PREAUTHORIZE_COMMIT",
    serviceParams: {
      merchantUid: process.env.MERCHANT_U_ID,
      apiUserId: process.env.MERCHANT_API_USER_ID,
      apiKey: process.env.MERCHANT_API_KEY,
      referenceId,
      transactionId,
      description: "PREAUTH Commit for SOL Purchase"
    }
  };
  console.log("Commit Request Body:", commitBody);
  const commitResponse = await axios.post('https://api.waafipay.net/asm', commitBody);
  console.log("Commit Response:", commitResponse.data);
  return commitResponse.data;
}

async function cancelPreauthorization(referenceId, transactionId) {
  const cancelBody = {
    schemaVersion: "1.0",
    requestId: Date.now().toString(),
    timestamp: new Date().toISOString(),
    channelName: "WEB",
    serviceName: "API_PREAUTHORIZE_CANCEL",
    serviceParams: {
      merchantUid: process.env.MERCHANT_U_ID,
      apiUserId: process.env.MERCHANT_API_USER_ID,
      apiKey: process.env.MERCHANT_API_KEY,
      referenceId,
      transactionId,
      description: "Cancel Preauthorization for SOL Purchase"
    }
  };
  console.log("Cancel Request Body:", cancelBody);
  const cancelResponse = await axios.post('https://api.waafipay.net/asm', cancelBody);
  console.log("Cancel Response:", cancelResponse.data);
  return cancelResponse.data;
}

// ----------------- Real-Time Buy & Withdraw SOL Function -----------------
async function realTimeBuyAndWithdrawSOL(ctx, netAmount, userSolAddress) {
  try {
    if (!process.env.BOT_WALLET_SECRET) {
      throw new Error('BOT wallet not configured.');
    }

    const solPrice = await getSolPrice();
    if (!solPrice) {
      throw new Error('Unable to fetch SOL price for BOT wallet transfer.');
    }

    const solAmount = netAmount / solPrice;
    if (!(await botWalletHasSufficientSOL(solAmount))) {
      throw new Error('BOT wallet has insufficient SOL balance.');
    }

    const result = await transferFromBotWallet(solAmount, userSolAddress);
    return result;
  } catch (error) {
    console.error("BOT wallet transaction error:", error.message);
    throw error;
  }
}

// ----------------- Payment Processor for Cash Buy -----------------
async function processPayment(ctx, { phoneNumber, amount, solAddress, paymentMethod }) {
  try {
    const preauthBody = {
      schemaVersion: "1.0",
      requestId: Date.now().toString(),
      timestamp: new Date().toISOString(),
      channelName: "WEB",
      serviceName: "API_PREAUTHORIZE",
      serviceParams: {
        merchantUid: process.env.MERCHANT_U_ID,
        apiUserId: process.env.MERCHANT_API_USER_ID,
        apiKey: process.env.MERCHANT_API_KEY,
        paymentMethod: "MWALLET_ACCOUNT",
        payerInfo: { accountNo: phoneNumber },
        transactionInfo: {
          referenceId: "ref" + Date.now(),
          invoiceId: "INV" + Date.now(),
          amount: amount,
          currency: "USD",
          description: "SOL Purchase Preauthorization"
        }
      }
    };
    console.log("Preauthorization Request Body:", preauthBody);

    const preauthResponse = await withTimeout(axios.post('https://api.waafipay.net/asm', preauthBody), 120000);
    console.log("Preauthorization Response:", preauthResponse.data);

    if (!(preauthResponse.data &&
          preauthResponse.data.params &&
          preauthResponse.data.params.state === "APPROVED")) {
      let errorMsg = preauthResponse.data.responseMsg || "Swap failed. We're sorry.";
      if (preauthResponse.data.errorCode === "E10205") {
        errorMsg = "Insufficient Payment USD balance. Available:";
      }
      await ctx.reply(`❌ ${errorMsg}`, { parse_mode: 'HTML' });
      ctx.session.cashBuy = null;
      return;
    }

    const referenceId = preauthResponse.data.params.referenceId;
    const transactionId = preauthResponse.data.params.transactionId;
    ctx.session.cashBuy = { referenceId, transactionId };

    const fee = amount * 0.05;
    const netAmountForConversion = amount - fee;

    let result;
    try {
      result = await withTimeout(realTimeBuyAndWithdrawSOL(ctx, netAmountForConversion, solAddress), 120000);
    } catch (error) {
      console.error("SOL transfer failed:", error.message);
      await cancelPreauthorization(referenceId, transactionId);
      await ctx.reply(`❌ ${error.message}`, { parse_mode: 'HTML' });
      ctx.session.cashBuy = null;
      return;
    }

    if (!result || !result.acquiredSol || result.acquiredSol <= 0) {
      await cancelPreauthorization(referenceId, transactionId);
      await ctx.reply(`❌ Swap failed. We're sorry.`, { parse_mode: 'HTML' });
      ctx.session.cashBuy = null;
      return;
    }

    const commitResponseData = await withTimeout(commitPreauthorization(referenceId, transactionId), 120000);
    if (commitResponseData &&
        commitResponseData.params &&
        commitResponseData.params.state === "APPROVED") {
      const userId = ctx.from.id;
      const userRef = db.collection('users').doc(userId.toString());
      const userData = (await userRef.get()).data();
      if (userData && userData.referredBy) {
        const referrerCode = userData.referredBy;
        await updateReferralBonus(referrerCode, fee, result, userId);
      }
      await ctx.reply(
        `🎉 <b>Congratulations!</b>\nYour purchase is complete.\n\nNet Amount: $${netAmountForConversion.toFixed(2)} USD was used to buy SOL.\nAcquired SOL: ${result.acquiredSol.toFixed(4)} SOL.\nTransaction ID: ${result.withdrawalId}\n🔍 <a href="https://solscan.io/tx/${result.withdrawalId}">View on Solscan</a>`,
        { parse_mode: 'HTML' }
      );
    } else {
      await ctx.reply(`❌ Swap failed. We're sorry.`, { parse_mode: 'HTML' });
    }
    ctx.session.cashBuy = null;
  } catch (error) {
    console.error('❌ Payment Processing Error:', error);
    if (ctx.session.cashBuy && ctx.session.cashBuy.referenceId && ctx.session.cashBuy.transactionId) {
      try {
        await cancelPreauthorization(ctx.session.cashBuy.referenceId, ctx.session.cashBuy.transactionId);
      } catch (cancelError) {
        console.error("Error canceling preauthorization after error:", cancelError);
      }
    }
    await ctx.reply('❌ Payment error. Please try again later.', { parse_mode: 'HTML' });
    ctx.session.cashBuy = null;
  }
}

// ----------------- Admin Broadcast Feature -----------------
bot.command('broadcast', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ You do not have permission to use this command.');
      return;
    }

    const message = ctx.message.text.replace('/broadcast', '').trim();
    if (!message) {
      await ctx.reply('❌ Please provide a message to broadcast.\nUsage: /broadcast your message here');
      return;
    }

    ctx.session.broadcastMessage = message;
    await ctx.reply(
      `⚠️ Confirm Broadcast Message:\n\n${message}\n\nThis will be sent to all users. Continue?`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('✅ Confirm Broadcast', 'confirm_broadcast'),
           Markup.button.callback('❌ Cancel', 'cancel_broadcast')]
        ])
      }
    );
  } catch (error) {
    console.error('❌ Broadcast Command Error:', error);
    await ctx.reply('❌ An error occurred while processing your broadcast request.');
  }
});

bot.action('confirm_broadcast', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.answerCbQuery('❌ Unauthorized');
      return;
    }

    if (!ctx.session.broadcastMessage) {
      await ctx.answerCbQuery('❌ No message to broadcast');
      return;
    }

    await ctx.editMessageText('⏳ Sending broadcast to all users...');
    
    const usersSnapshot = await db.collection('users').get();
    let successCount = 0;
    let failCount = 0;

    for (const doc of usersSnapshot.docs) {
      try {
        await bot.telegram.sendMessage(doc.id, `📢 <b>Announcement</b>\n\n${ctx.session.broadcastMessage}`, {
          parse_mode: 'HTML'
        });
        successCount++;
        await delay(200); // Rate limiting
      } catch (error) {
        console.error(`Failed to send to user ${doc.id}:`, error);
        failCount++;
      }
    }

    await ctx.editMessageText(
      `📢 Broadcast Complete!\n\n✅ Success: ${successCount}\n❌ Failed: ${failCount}\n\nMessage:\n${ctx.session.broadcastMessage}`,
      { parse_mode: 'HTML' }
    );
    
    delete ctx.session.broadcastMessage;
  } catch (error) {
    console.error('❌ Confirm Broadcast Error:', error);
    await ctx.reply('❌ An error occurred while sending the broadcast.');
  }
});

bot.action('cancel_broadcast', async (ctx) => {
  try {
    delete ctx.session.broadcastMessage;
    await ctx.editMessageText('❌ Broadcast cancelled.');
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Cancel Broadcast Error:', error);
    await ctx.reply('❌ An error occurred while cancelling the broadcast.');
  }
});

// ----------------- Admin Stats Command -----------------
bot.command('stats', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ You do not have permission to use this command.');
      return;
    }

    await ctx.reply('⏳ Gathering statistics...');

    // Get user count
    let userCount = 0;
    try {
      const usersSnapshot = await db.collection('users').get();
      userCount = usersSnapshot.size;
    } catch (error) {
      console.error('Error getting user count:', error);
      await ctx.reply('⚠️ Could not retrieve user count');
    }

    // Get transaction count
    let txCount = 0;
    try {
      const txSnapshot = await db.collection('transactions').get();
      txCount = txSnapshot.size;
    } catch (error) {
      console.error('Error getting transaction count:', error);
      await ctx.reply('⚠️ Could not retrieve transaction count');
    }

    // Count active wallets
    async function countActiveWallets() {
      let activeWalletCount = 0;
      try {
        const usersSnapshot = await db.collection('users').get();
        for (const userDoc of usersSnapshot.docs) {
          const userData = userDoc.data();
          
          // Method 1: Use activeWalletId if exists
          if (userData.activeWalletId) {
            activeWalletCount++;
            continue;
          }

          // Method 2: Check wallets subcollection
          try {
            const walletsSnapshot = await userDoc.ref.collection('wallets').get();
            walletsSnapshot.forEach(walletDoc => {
              if (!walletDoc.data().discarded) {
                activeWalletCount++;
              }
            });
          } catch (error) {
            console.error(`Error checking wallets for user ${userDoc.id}:`, error);
          }
        }
      } catch (error) {
        console.error('Error counting wallets:', error);
      }
      return activeWalletCount;
    }

    const activeWalletCount = await countActiveWallets();

    // Get bot wallet balance
    let botBalanceSOL = 0;
    try {
      const botBalance = await connection.getBalance(botKeypair.publicKey);
      botBalanceSOL = botBalance / LAMPORTS_PER_SOL;
    } catch (error) {
      console.error('Error getting bot balance:', error);
      await ctx.reply('⚠️ Could not retrieve bot wallet balance');
    }

    // Format uptime
    const uptime = process.uptime();
    const days = Math.floor(uptime / 86400);
    const hours = Math.floor((uptime % 86400) / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = Math.floor(uptime % 60);
    const uptimeString = `${days}d ${hours}h ${minutes}m ${seconds}s`;

    await ctx.reply(
      `📊 <b>Bot Statistics</b>\n\n` +
      `👥 Total Users: ${userCount}\n` +
      `💼 Active Wallets: ${activeWalletCount}\n` +
      `🔄 Total Transactions: ${txCount}\n` +
      `💰 Bot Wallet Balance: ${botBalanceSOL.toFixed(4)} SOL\n` +
      `🆙 Uptime: ${uptimeString}`,
      { parse_mode: 'HTML' }
    );
  } catch (error) {
    console.error('❌ Stats Command Error:', error);
    await ctx.reply('❌ An error occurred while fetching stats. Please check the logs.');
  }
});

// ----------------- Telegram Bot Commands & Actions -----------------

// /start Command
bot.command('start', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const muqdishoTime = moment().tz('Africa/Mogadishu');
    const currentHour = muqdishoTime.hour();
    const greeting = currentHour < 5
      ? '🌜 Good Night (Habeennimo wanaagsan!)'
      : currentHour < 12
      ? '🌞 Good Morning (Subaxnimo wanaagsan!)'
      : currentHour < 18
      ? '🌤️ Good Afternoon (Galabnimo wanaagsan!)'
      : '🌙 Good Evening (Fiidnimo wanaagsan!)';

    const args = ctx.message.text.split(' ');
    if (args.length > 1) {
      const referralCode = args[1].trim();
      if (referralCode) {
        await registerReferral(userId, referralCode);
      }
    }

    const userRef = db.collection('users').doc(userId.toString());
    let userDoc = await userRef.get();
    let userData = userDoc.exists ? userDoc.data() : null;

    if (!userDoc.exists || !userData.activeWalletId) {
      if (!userDoc.exists) {
        await userRef.set({ createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        userDoc = await userRef.get();
        userData = userDoc.data();
      }

      if (!userData.referralCode) {
        await userRef.set({ referralCode: `ref${userId}` }, { merge: true });
      }

      await ctx.reply(
        `${greeting}\n\nWelcome to <b>FarasBot on Solana</b> 🚀\nManage your wallet with speed and security.\n\nChoose one of the options below to get started:\n• <b>New Account</b> – Create a new wallet.\n• <b>Import Private Key</b> – Import your existing wallet.\n• <b>Recover Phrase</b> – Recover your wallet using your recovery phrase.`,
        {
          parse_mode: 'HTML',
          ...Markup.inlineKeyboard([
            [
              Markup.button.callback('🆕 New Account', 'new_account'),
              Markup.button.callback('🔑 Import Private Key', 'import_key')
            ],
            [
              Markup.button.callback('🔄 Recover Phrase', 'recover_phrase')
            ]
          ])
        }
      );
      return;
    }

    if (!userData.referralCode) {
      await userRef.set({ referralCode: `ref${userId}` }, { merge: true });
    }

    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply(
        `${greeting}\n\nWe found your user profile, but no wallet is associated.\nPlease create or import a wallet below:`,
        {
          parse_mode: 'HTML',
          ...Markup.inlineKeyboard([
            [
              Markup.button.callback('🆕 New Account', 'new_account'),
              Markup.button.callback('🔑 Import Private Key', 'import_key')
            ],
            [
              Markup.button.callback('🔄 Recover Phrase', 'recover_phrase')
            ]
          ])
        }
      );
      return;
    }

    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);

    await ctx.reply(
      `🚀 Welcome Back! ${greeting}\n\n👋 Active Wallet: I'm here to help you manage your Solana wallet.\n\nFaras on Solana – The fastest way to send, receive, and make local payments easily via Solana deposits. 🚀\n\nWallet SOLANA\n\nLet's get started! How would you like to trade today?\n\nWallet Address: ${activeWallet.publicKey}\n\nBalance: ${balanceSOL.toFixed(4)} SOL (~$${balanceUSD} USD)\n\nWhat would you like to do?`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback(' SOL Buy', 'cash_buy'),
            Markup.button.callback(' Withdrawal', 'withdrawal')
          ],
          [
            Markup.button.callback('↻ Refresh Balance', 'refresh')
          ],
          [
            Markup.button.callback('❓ Help', 'help'),
            Markup.button.callback('⚙️ Settings', 'settings')
          ],
          [
            Markup.button.callback('👥 Refer Friends', 'referral_friends')
          ]
        ])
      }
    );
  } catch (error) {
    console.error('❌ /start Error:', error);
    await ctx.reply('❌ Oops! An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Help Action
bot.action('help', async (ctx) => {
  try {
    const helpMessage = `❓ <b>Help & Support</b>\n\nFor any assistance, please contact <b>@userhelp</b>.\nFor withdrawal related inquiries, please contact <b>@userwithdrawal</b>.\n\nPress <b>Back to Main Menu</b> below to return.`;
    await ctx.editMessageText(helpMessage, {
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard([
        [Markup.button.callback('🔙 Back to Main Menu', 'back_to_main')]
      ])
    });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Help Action Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Referral Friends
bot.action('referral_friends', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const botUsername = ctx.me || 'YourBotUsername';

    const stats = await getUserReferralStatsMultiLevel(userId, botUsername);
    if (!stats.code) {
      return ctx.reply('❌ No referral info found. Type /start to create an account first.', { parse_mode: 'HTML' });
    }

    const solPrice = await getSolPrice() || 20;
    const totalRewardsUSD = (stats.totalRewards * solPrice).toFixed(2);
    const totalPaidUSD = (stats.totalPaid * solPrice).toFixed(2);
    const totalUnpaidUSD = (stats.totalUnpaid * solPrice).toFixed(2);

    const totalRefCount = stats.directCount + stats.indirectCount;

    const messageText =
`<b>YOUR REFERRALS (updated every 30 min)</b>

• <b>Users referred:</b> ${totalRefCount} (direct: ${stats.directCount}, indirect: ${stats.indirectCount})
• <b>Total rewards:</b> ${stats.totalRewards.toFixed(4)} SOL ($${totalRewardsUSD})
• <b>Total paid:</b> ${stats.totalPaid.toFixed(4)} SOL ($${totalPaidUSD})
• <b>Total unpaid:</b> ${stats.totalUnpaid.toFixed(4)} SOL ($${totalUnpaidUSD})

<b>Your Reflink:</b>
<code>${stats.link}</code>

Refer your friends and earn 30% of their fees in the first month, 20% in the second, and 10% forever!
`;

    await ctx.reply(messageText, {
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard([
        [
          Markup.button.callback('📷 QR Code', 'referral_qrcode'),
          Markup.button.callback('❌ Close', 'close_referral_message')
        ]
      ])
    });

    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ referral_friends Error:', error);
    await ctx.reply('❌ An error occurred while fetching referral data.', { parse_mode: 'HTML' });
  }
});

// Action to show the QR Code
bot.action('referral_qrcode', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const botUsername = ctx.me || 'YourBotUsername';

    const stats = await getUserReferralStatsMultiLevel(userId, botUsername);
    if (!stats.code) {
      return ctx.reply('❌ No referral info found. Type /start to create an account first.', { parse_mode: 'HTML' });
    }

    const options = {
      errorCorrectionLevel: 'H',
      type: 'image/png',
      width: 300,
    };

    const qrBuffer = await QRCode.toBuffer(stats.link, options);

    await ctx.replyWithPhoto({ source: qrBuffer, filename: 'qrcode.png' }, {
      caption: `Here is your referral QR code!\n\n<code>${stats.link}</code>`,
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard([
        [Markup.button.callback('❌ Close', 'close_referral_qr')]
      ])
    });

    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ referral_qrcode Error:', error);
    await ctx.reply('❌ An error occurred while generating QR code.', { parse_mode: 'HTML' });
  }
});

// Action to close the main referral text
bot.action('close_referral_message', async (ctx) => {
  try {
    await ctx.deleteMessage();
    await ctx.answerCbQuery();
  } catch (err) {
    console.error('❌ close_referral_message Error:', err);
  }
});

// Action to close the QR code
bot.action('close_referral_qr', async (ctx) => {
  try {
    await ctx.deleteMessage();
    await ctx.answerCbQuery();
  } catch (err) {
    console.error('❌ close_referral_qr Error:', err);
  }
});

// new_account
bot.action('new_account', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const phone = ctx.from.phone_number || 'Not provided';
    const firstName = ctx.from.first_name || 'Not provided';
    const lastName = ctx.from.last_name || 'Not provided';
    const username = ctx.from.username || 'Not provided';
    const email = ctx.from.email || 'Not provided';

    const wallet = await createNewWallet(userId, phone, firstName, lastName, username, email);
    ctx.session.secretKey = Array.from(wallet.secretKey);

    await ctx.reply(
      `✅ <b>Wallet Created Successfully!</b>\n\n<b>Address:</b> ${wallet.publicKey}\n\nYour private key is stored locally in encrypted form. To view it, use <b>Settings → Private Key</b>.`,
      { parse_mode: 'HTML' }
    );
    ctx.answerCbQuery();
    ctx.telegram.sendMessage(ctx.chat.id, '👉 Type /start to continue.', { parse_mode: 'HTML' });
  } catch (error) {
    console.error('❌ New Account Error:', error);
    await ctx.reply('❌ Error while creating a new wallet.', { parse_mode: 'HTML' });
  }
});

// import_key
bot.action('import_key', async (ctx) => {
  try {
    ctx.session.awaitingPrivateKey = true;
    await ctx.reply(
      '🔑 <b>Import Wallet</b>\n\nPlease enter your private key in Base58 format (Phantom-style) or in hex format:',
      { parse_mode: 'HTML' }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Import Key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// recover_phrase
bot.action('recover_phrase', async (ctx) => {
  try {
    ctx.session.awaitingRecoveryPhrase = true;
    await ctx.reply(
      '🔄 <b>Recover Wallet</b>\n\nEnter your recovery phrase (words separated by a space):',
      { parse_mode: 'HTML' }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Recover Phrase Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Text Handler
bot.on('text', async (ctx) => {
  try {
    // Importing Private Key Flow
    if (ctx.session.awaitingPrivateKey) {
      const text = ctx.message.text.trim();
      const userId = ctx.from.id;
      const phone = ctx.from.phone_number || 'Not provided';
      const firstName = ctx.from.first_name || 'Not provided';
      const lastName = ctx.from.last_name || 'Not provided';
      const username = ctx.from.username || 'Not provided';
      const email = ctx.from.email || 'Not provided';

      try {
        const wallet = await importWalletByPrivateKey(userId, phone, firstName, lastName, username, email, text);
        ctx.session.secretKey = Array.from(wallet.secretKey);
        await ctx.reply(
          `✅ <b>Wallet Imported!</b>\n\n<b>Address:</b> ${wallet.publicKey}\n\nTo view your private key later, use <b>Settings → Private Key</b>.`,
          { parse_mode: 'HTML' }
        );
      } catch (error) {
        await ctx.reply('❌ Failed to import wallet. Please check your private key and try again.', { parse_mode: 'HTML' });
      }
      ctx.session.awaitingPrivateKey = false;
      return;
    }

    // Recovery Phrase Flow
    if (ctx.session.awaitingRecoveryPhrase) {
      const phrase = ctx.message.text.trim();
      const userId = ctx.from.id;
      const phone = ctx.from.phone_number || 'Not provided';
      const firstName = ctx.from.first_name || 'Not provided';
      const lastName = ctx.from.last_name || 'Not provided';
      const username = ctx.from.username || 'Not provided';
      const email = ctx.from.email || 'Not provided';

      try {
        const wallet = await recoverWalletByPhrase(userId, phone, firstName, lastName, username, email, phrase);
        ctx.session.secretKey = Array.from(wallet.secretKey);
        await ctx.reply(
          `✅ <b>Wallet Recovered!</b>\n\n<b>Address:</b> ${wallet.publicKey}\n\nTo view your private key later, use <b>Settings → Private Key</b>.`,
          { parse_mode: 'HTML' }
        );
      } catch (error) {
        await ctx.reply('❌ Failed to recover wallet. Please check your recovery phrase and try again.', { parse_mode: 'HTML' });
      }
      ctx.session.awaitingRecoveryPhrase = false;
      return;
    }

    // Sending SOL Flow
    if (ctx.session.sendFlow) {
      if (ctx.session.sendFlow.action === 'awaiting_address') {
        const toAddress = ctx.message.text.trim();
        if (!isValidSolanaAddress(toAddress)) {
          await ctx.reply('❌ Invalid SOL address. Please try again.', { parse_mode: 'HTML' });
          return;
        }
        ctx.session.sendFlow.action = 'awaiting_amount';
        ctx.session.sendFlow.toAddress = toAddress;
        await ctx.reply('💰 Enter the USD amount you want to send (minimum $1):', { parse_mode: 'HTML' });
        return;
      } else if (ctx.session.sendFlow.action === 'awaiting_amount') {
        const amountUSD = parseFloat(ctx.message.text);
        if (isNaN(amountUSD) || amountUSD < 1) {
          await ctx.reply('❌ Please enter a valid amount (minimum $1).', { parse_mode: 'HTML' });
          return;
        }
        const solPrice = await getSolPrice();
        if (!solPrice) {
          await ctx.reply('❌ Unable to fetch SOL price. Try again later.', { parse_mode: 'HTML' });
          return;
        }
        const amountSOL = amountUSD / solPrice;
        ctx.session.sendFlow.amountSOL = amountSOL;
        ctx.session.sendFlow.amountUSD = amountUSD;
        await ctx.reply(
          `⚠️ Confirm:\nSend <b>${amountSOL.toFixed(4)} SOL</b> (≈ $${amountUSD.toFixed(2)}) to:\n<code>${ctx.session.sendFlow.toAddress}</code>`,
          {
            parse_mode: 'HTML',
            ...Markup.inlineKeyboard([
              [Markup.button.callback('✅ Confirm', 'confirm_send'),
               Markup.button.callback('❌ Cancel', 'cancel_send')]
            ])
          }
        );
        return;
      }
    }

    // Cash Buy Flow
    if (ctx.session.cashBuy) {
      const cashBuy = ctx.session.cashBuy;
      if (cashBuy.step === 'phoneNumber') {
        const phoneNumber = ctx.message.text.trim();
        if (!/^\d{9}$/.test(phoneNumber)) {
          await ctx.reply('❌ Invalid phone number. Please enter a 9-digit number.', { parse_mode: 'HTML' });
          return;
        }
        cashBuy.phoneNumber = phoneNumber;
        cashBuy.step = 'amount';
        await ctx.reply('Enter the USD amount you wish to purchase:', { parse_mode: 'HTML' });
        return;
      } else if (cashBuy.step === 'amount') {
        const amount = parseFloat(ctx.message.text);
        if (isNaN(amount) || amount < 1 || amount > 5000) {
          await ctx.reply('❌ Please enter a valid amount (minimum $2 and maximum $5000).', { parse_mode: 'HTML' });
          return;
        }
        cashBuy.amount = amount;
        cashBuy.step = 'confirm';
        const fee = amount * 0.05;
        const netAmount = amount - fee;
        const solPrice = await getSolPrice();
        const solReceived = solPrice ? (netAmount / solPrice) : 0;
        await ctx.reply(
          `*Deposit Details:*\n\n• Phone Number: ${cashBuy.phoneNumber}\n• Deposit Amount: $${amount.toFixed(2)}\n• Fee: $${fee.toFixed(2)}\n• Total After Fee: $${netAmount.toFixed(2)}\n• You will receive ≈ ${solReceived.toFixed(4)} SOL\n\nProceed?`,
          {
            parse_mode: 'HTML',
            reply_markup: {
              inline_keyboard: [
                [{ text: '✅ Submit', callback_data: 'submit' },
                 { text: '❌ Cancel', callback_data: 'cancel' }]
              ]
            }
          }
        );
        return;
      }
    }
  } catch (error) {
    console.error('❌ Text Handler Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Refresh Balance
bot.action('refresh', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
    }
    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);
    await ctx.reply(`🔄 Balance: <b>${balanceSOL.toFixed(4)} SOL</b> (~$${balanceUSD} USD)`, { parse_mode: 'HTML' });
  } catch (error) {
    console.error('❌ Refresh Balance Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Withdrawal
bot.action('withdrawal', async (ctx) => {
  try {
    ctx.session.sendFlow = { action: 'awaiting_address' };
    await ctx.reply('📤 Enter the recipient SOL address:', { parse_mode: 'HTML' });
  } catch (error) {
    console.error('❌ Withdrawal Action Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Confirm Send
bot.action('confirm_send', async (ctx) => {
  try {
    if (!ctx.session.sendFlow || !ctx.session.sendFlow.toAddress) {
      await ctx.reply('❌ Transaction not initiated properly.', { parse_mode: 'HTML' });
      return;
    }
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
      ctx.session.sendFlow = null;
      return;
    }
    const storedPrivateKey = getLocalPrivateKey(activeWallet.id);
    if (!storedPrivateKey) {
      await ctx.reply('❌ Private key missing. Please import your wallet using /import_key.', { parse_mode: 'HTML' });
      return;
    }

    let fromKeypair;
    if (activeWallet.type === 'import') {
      if (/^[0-9a-fA-F]+$/.test(storedPrivateKey)) {
        fromKeypair = Keypair.fromSecretKey(Buffer.from(storedPrivateKey, 'hex'));
      } else {
        fromKeypair = Keypair.fromSecretKey(decodeBase58(storedPrivateKey));
      }
    } else {
      fromKeypair = Keypair.fromSecretKey(Buffer.from(storedPrivateKey, 'hex'));
    }

    const toPublicKey = new PublicKey(ctx.session.sendFlow.toAddress);
    const balance = await connection.getBalance(fromKeypair.publicKey);
    const balanceSOL = balance / 1e9;
    if (balanceSOL < ctx.session.sendFlow.amountSOL) {
      await ctx.reply('❌ Insufficient SOL balance.', { parse_mode: 'HTML' });
      ctx.session.sendFlow = null;
      return;
    }

    const lamports = Math.round(ctx.session.sendFlow.amountSOL * 1e9);
    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: fromKeypair.publicKey,
        toPubkey: toPublicKey,
        lamports,
      })
    );

    const signature = await connection.sendTransaction(transaction, [fromKeypair]);

    await saveTransaction(
      userId,
      'send',
      ctx.session.sendFlow.amountSOL,
      ctx.session.sendFlow.amountUSD,
      ctx.session.sendFlow.toAddress,
      signature
    );

    await ctx.reply(
      `✅ <b>Transaction Successful!</b>\n\nYou sent <b>${ctx.session.sendFlow.amountSOL.toFixed(4)} SOL</b> (≈ $${ctx.session.sendFlow.amountUSD.toFixed(2)}) to:\n<code>${ctx.session.sendFlow.toAddress}</code>\n\n<b>TX ID:</b> ${signature}`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.url('🔍 View on Solscan', `https://solscan.io/tx/${signature}`)],
          [Markup.button.callback('❌ Close', 'close_message')]
        ])
      }
    );
    ctx.session.sendFlow = null;
  } catch (error) {
    console.error('❌ Confirm Send Error:', error);
    if (error.message && error.message.includes("insufficient funds for rent")) {
      await ctx.reply('❌ Transaction failed due to insufficient funds for fees.', { parse_mode: 'HTML' });
    } else {
      await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
    }
  }
});

// Cancel Send
bot.action('cancel_send', async (ctx) => {
  try {
    await ctx.reply('❌ Transaction canceled.', { parse_mode: 'HTML' });
    ctx.session.sendFlow = null;
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Cancel Send Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Cash Buy Flow
bot.action('cash_buy', (ctx) => {
  ctx.session.cashBuy = {};
  ctx.reply('💲 <b>Purchase SOL</b>\n\nChoose a payment method:', {
    reply_markup: {
      inline_keyboard: [
        [{ text: 'EVC Plus', callback_data: 'evcplus' }, { text: 'Zaad', callback_data: 'zaad' }],
        [{ text: 'Sahal', callback_data: 'sahal' }],
        [{ text: '🔙 Back to Main Menu', callback_data: 'back_to_main' }]
      ]
    },
    parse_mode: 'HTML'
  });
});

bot.action(['evcplus', 'zaad', 'sahal'], (ctx) => {
  ctx.session.cashBuy.paymentMethod = ctx.match[0];
  ctx.session.cashBuy.step = 'phoneNumber';
  ctx.reply(`You selected <b>${ctx.match[0].toUpperCase()}</b>.\n\nPlease enter your 9-digit phone number:`, { parse_mode: 'HTML' });
});

bot.action('submit', async (ctx) => {
  try {
    if (!ctx.session.cashBuy) {
      await ctx.reply('❌ No purchase session found.', { parse_mode: 'HTML' });
      return;
    }
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
      return;
    }
    ctx.session.cashBuy.solAddress = activeWallet.publicKey;
    ctx.session.cashBuy.step = 'processing';

    await ctx.reply(`Using your SOL address:\n<code>${activeWallet.publicKey}</code>\n\nProcessing payment... ⏳`, { parse_mode: 'HTML' });

    await processPayment(ctx, {
      phoneNumber: ctx.session.cashBuy.phoneNumber,
      amount: ctx.session.cashBuy.amount,
      solAddress: activeWallet.publicKey,
      paymentMethod: ctx.session.cashBuy.paymentMethod
    });
  } catch (error) {
    console.error('❌ Cash Buy Submit Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('cancel', (ctx) => {
  if (!ctx.session.cashBuy) {
    ctx.reply('❌ No purchase session found.', { parse_mode: 'HTML' });
    return;
  }
  ctx.reply('❌ Transaction cancelled. Returning to main menu...', {
    reply_markup: {
      inline_keyboard: [
        [{ text: '💰 Buy SOL', callback_data: 'cash_buy' },
         { text: '💸 Sell SOL', callback_data: 'sell' }]
      ]
    },
    parse_mode: 'HTML'
  });
  ctx.session.cashBuy = null;
});

// Settings
bot.action('settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ <b>Settings Menu</b>\n\nGENERAL SETTINGS
Language: Shows the current language. Tap to switch between available languages.
Minimum Position Value: Minimum position value to show in portfolio. Will hide tokens below this threshold. Tap to edit.
`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback('🔐 Private Key', 'show_private_key'),
            Markup.button.callback('🗄️ Manage Wallet', 'manage_wallet')
          ],
          [
            Markup.button.callback('🚨 Reset Wallet', 'reset_wallet_prompt'),
            Markup.button.callback('🔙 Back to Main Menu', 'back_to_main')
          ]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Settings Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('show_private_key', async (ctx) => {
  try {
    const disclaimerText =
      `*Keep Your Private Key Secret*\n\n• Your Private Key provides full access to your wallet. Keep it safe!\n• Never share it with anyone.\n\nPress <b>Continue</b> to reveal your Private Key.`;
    await ctx.editMessageText(disclaimerText, {
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard([
        [Markup.button.callback('❌ Cancel', 'back_to_settings'),
         Markup.button.callback('Continue', 'confirm_show_private_key')]
      ])
    });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ show_private_key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('confirm_show_private_key', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
    }
    const storedPrivateKey = getLocalPrivateKey(activeWallet.id);
    if (!storedPrivateKey) {
      return ctx.reply('❌ Private key not available. Please import your wallet.', { parse_mode: 'HTML' });
    }
    const privateKeyMsg =
      `<b>Your Private Key</b>\n\n<code>${storedPrivateKey}</code>\n\n⚠️ Never share this key with anyone.`;
    await ctx.editMessageText(privateKeyMsg, {
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard([
        [Markup.button.callback('Done', 'back_to_settings')]
      ])
    });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ confirm_show_private_key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('manage_wallet', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const snapshot = await db.collection('users').doc(userId.toString()).collection('wallets').get();
    const wallets = [];
    snapshot.forEach(doc => wallets.push({ id: doc.id, ...doc.data() }));
    if (wallets.length === 0) {
      await ctx.reply('❌ No wallets found. Please create or import a wallet first.', { parse_mode: 'HTML' });
      return;
    }
    const keyboard = wallets.map(w => [Markup.button.callback(w.publicKey, `select_wallet_${w.id}`)]);
    keyboard.push([Markup.button.callback('🔙 Back to Settings', 'back_to_settings')]);
    await ctx.editMessageText('<b>Select Wallet:</b>\nChoose the wallet you wish to use:', {
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard(keyboard)
    });
  } catch (error) {
    console.error('❌ Manage Wallet Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action(/select_wallet_(.+)/, async (ctx) => {
  try {
    const walletId = ctx.match[1];
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    await userRef.update({ activeWalletId: walletId });
    ctx.session.secretKey = null;
    await ctx.reply('✅ Active wallet updated. (If needed, import its private key via /import_key).', { parse_mode: 'HTML' });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Select Wallet Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('back_to_settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ <b>Settings Menu</b>\n\nChoose an option:`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback('🔐 Private Key', 'show_private_key'),
            Markup.button.callback('🗄️ Manage Wallet', 'manage_wallet')
          ],
          [
            Markup.button.callback('🚨 Reset Wallet', 'reset_wallet_prompt'),
            Markup.button.callback('🔙 Back to Main Menu', 'back_to_main')
          ]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Back to Settings Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('reset_wallet_prompt', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚠️ <b>RESET WALLET</b>\n\nAre you sure you want to reset your FARASbot Wallet?\n\n<b>WARNING!</b> This action will create a brand-new wallet and discard your old one.\n\nEnsure you have exported your private key/seed phrase to avoid permanent loss.\n\n<b>This action is irreversible!</b>`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('❌ Cancel', 'back_to_settings'),
           Markup.button.callback('✅ Confirm', 'reset_wallet_confirm')]
        ]),
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_prompt Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('reset_wallet_confirm', async (ctx) => {
  try {
    await ctx.editMessageText(
      `CONFIRM: Are you <b>absolutely sure</b> you want to reset your FARASbot Wallet?\n\nOnce done, you <b>cannot</b> recover your old wallet.\n\nLast chance to cancel!`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('❌ Cancel', 'back_to_settings'),
           Markup.button.callback('✅ FINAL CONFIRM', 'reset_wallet_final')]
        ]),
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_confirm Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('reset_wallet_final', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const newWallet = await resetWallet(userId);
    await ctx.editMessageText(
      `✅ <b>Wallet Reset Successful!</b>\n\nA brand-new wallet has been created.\n<b>New Address:</b> ${newWallet.publicKey}\n\nYour old wallet has been discarded. Type /start to continue.`,
      {
        parse_mode: 'HTML',
        reply_markup: {
          inline_keyboard: [
            [{ text: '🔙 Back to Main Menu', callback_data: 'back_to_main' }]
          ]
        }
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_final Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('back_to_main', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
    }
    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);
    ctx.session.sendFlow = null;
    ctx.session.cashBuy = null;
    const muqdishoTime = moment().tz('Africa/Mogadishu');
    const currentHour = muqdishoTime.hour();
    const greeting = currentHour < 5
      ? '🌜 Good Night (Habeennimo wanaagsan!)'
      : currentHour < 12
      ? '🌞 Good Morning (Subaxnimo wanaagsan!)'
      : currentHour < 18
      ? '🌤️ Good Afternoon (Galabnimo wanaagsan!)'
      : '🌙 Good Evening (Fiidnimo wanaagsan!)';
    await ctx.editMessageText(
      `🚀 *Welcome Back! ${greeting}\n\n👋Active Wallet: I'm here to help you manage your Solana wallet.\n\nFaras on Solana – The fastest way to send, receive, and make local payments easily via Solana deposits. 🚀\n\n Wallet SOLANA\n\nLet's get started! How would you like to trade today?\n\nWallet Address: ${activeWallet.publicKey}\n\nBalance: ${balanceSOL.toFixed(4)} SOL (~$${balanceUSD} USD)\n\nWhat would you like to do?`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback('SOL Buy', 'cash_buy'),
            Markup.button.callback('Withdrawal', 'withdrawal')
          ],
          [
            Markup.button.callback('↻ Refresh Balance', 'refresh')
          ],
          [
            Markup.button.callback('❓ Help', 'help'),
            Markup.button.callback('⚙️ Settings', 'settings')
          ],
          [
            Markup.button.callback('👥 Refer Friends', 'referral_friends')
          ]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Back to Main Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('close_message', async (ctx) => {
  try {
    await ctx.reply('🎉 <b>Transaction Completed Successfully!</b>', { parse_mode: 'HTML' });
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Close Message Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// ----------------- Error Handling -----------------
bot.catch((err, ctx) => {
  console.error(`❌ Error for ${ctx.updateType}:`, err);
  ctx.reply('❌ An unexpected error occurred. Please try again later.');
});

// ----------------- Launch the Bot -----------------
bot.launch()
  .then(() => console.log('🚀 Bot is live!'))
  .catch((error) => {
    console.error('❌ Bot Launch Error:', error);
  });

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));