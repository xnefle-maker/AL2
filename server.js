const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
require('dotenv').config();

const app = express();
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const UPLOAD_DIR = path.join(ROOT, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'shop.json');
fs.mkdirSync(DATA_DIR, {recursive:true}); fs.mkdirSync(UPLOAD_DIR, {recursive:true});
const emptyDB = {categories:[],products:[],orders:[],settings:{cardNumber:'',cardOwner:'',botUsername:process.env.TELEGRAM_BOT_USERNAME||'ALBERIA3BOT',bankName:''}};
function readDB(){try{return {...emptyDB,...JSON.parse(fs.readFileSync(DB_FILE,'utf8'))}}catch{return structuredClone(emptyDB)}}
function writeDB(db){const tmp=DB_FILE+'.tmp';fs.writeFileSync(tmp,JSON.stringify(db,null,2));fs.renameSync(tmp,DB_FILE)}
if(!fs.existsSync(DB_FILE))writeDB(emptyDB);
const secret=process.env.SESSION_SECRET||'CHANGE_THIS_TO_A_LONG_RANDOM_SECRET_BEFORE_DEPLOY';
const adminPassword=process.env.ADMIN_PASSWORD||'';
if(!adminPassword || adminPassword==='CHANGE_THIS_TO_A_STRONG_PASSWORD' || !process.env.SESSION_SECRET || process.env.SESSION_SECRET.length<40 || process.env.SESSION_SECRET.includes('CHANGE_THIS')){console.error('Set a strong ADMIN_PASSWORD and a random SESSION_SECRET (40+ characters) in .env before starting.');process.exit(1)}
app.disable('x-powered-by');
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('X-Frame-Options','DENY');next()});
app.use(express.json({limit:'1mb'}));
app.use(express.urlencoded({extended:false,limit:'1mb'}));
app.use('/assets',express.static(path.join(ROOT,'assets'),{fallthrough:false,maxAge:'30d',immutable:true}));
app.use('/uploads',express.static(UPLOAD_DIR,{fallthrough:false,maxAge:'7d'}));
app.use(['/data','/server.js','/package.json','/.env','/.env.example','/SHOP_SETUP_FA.txt'],(req,res)=>res.sendStatus(404));
app.use(express.static(ROOT,{index:'index.html',dotfiles:'ignore'}));
function sign(payload){return crypto.createHmac('sha256',secret).update(payload).digest('hex')}
function cookie(req,name){const raw=req.headers.cookie||'';const part=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='));return part?decodeURIComponent(part.slice(name.length+1)):''}
function validSession(req){const v=cookie(req,'alberia_admin');if(!v)return false;const [exp,nonce,sig]=v.split('.');if(!exp||!nonce||!sig||Number(exp)<Date.now())return false;const expected=sign(exp+'.'+nonce);return crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))}
function requireAdmin(req,res,next){if(!validSession(req))return res.status(401).json({error:'ابتدا وارد پنل مدیریت شو.'});next()}
const loginAttempts=new Map();
app.post('/api/admin/login',(req,res)=>{const ip=req.ip||req.socket.remoteAddress;const a=loginAttempts.get(ip)||{n:0,until:0};if(a.until>Date.now())return res.status(429).json({error:'تعداد تلاش زیاد است؛ کمی بعد دوباره امتحان کن.'});if(!adminPassword)return res.status(503).json({error:'رمز مدیریت در فایل .env تنظیم نشده است.'});const given=String(req.body.password||'');const x=Buffer.from(given);const y=Buffer.from(adminPassword);const ok=x.length===y.length&&crypto.timingSafeEqual(x,y);if(!ok){a.n++;if(a.n>=6){a.until=Date.now()+10*60*1000;a.n=0}loginAttempts.set(ip,a);return res.status(401).json({error:'رمز عبور اشتباه است.'})}loginAttempts.delete(ip);const exp=Date.now()+8*60*60*1000,nonce=crypto.randomBytes(24).toString('hex'),payload=exp+'.'+nonce;res.setHeader('Set-Cookie',`alberia_admin=${encodeURIComponent(payload+'.'+sign(payload))}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${process.env.NODE_ENV==='production'?'; Secure':''}`);res.json({ok:true})});
app.post('/api/admin/logout',(req,res)=>{res.setHeader('Set-Cookie','alberia_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');res.json({ok:true})});
app.get('/api/shop',(req,res)=>{const d=readDB();res.json({categories:d.categories,products:d.products,settings:{}})});
app.get('/api/admin/data',requireAdmin,(req,res)=>{const d=readDB();res.json({categories:d.categories,products:d.products,orders:d.orders,settings:d.settings})});
app.put('/api/admin/settings',requireAdmin,(req,res)=>{const d=readDB();for(const k of ['cardNumber','cardOwner','botUsername','bankName'])d.settings[k]=String(req.body[k]||'').trim().slice(0,120);writeDB(d);res.json({ok:true})});
app.post('/api/admin/categories',requireAdmin,(req,res)=>{const title=String(req.body.title||'').trim();if(!title)return res.status(400).json({error:'نام دسته‌بندی رو وارد کن.'});const d=readDB();const c={id:crypto.randomUUID(),title:title.slice(0,80),image:String(req.body.image||'').slice(0,500)};d.categories.push(c);writeDB(d);res.json(c)});
app.put('/api/admin/categories/:id',requireAdmin,(req,res)=>{const d=readDB(),c=d.categories.find(x=>x.id===req.params.id);if(!c)return res.status(404).json({error:'دسته‌بندی پیدا نشد.'});if(req.body.title!==undefined)c.title=String(req.body.title).trim().slice(0,80);if(req.body.image!==undefined)c.image=String(req.body.image).slice(0,500);writeDB(d);res.json(c)});
app.delete('/api/admin/categories/:id',requireAdmin,(req,res)=>{const d=readDB();d.categories=d.categories.filter(c=>c.id!==req.params.id);d.products=d.products.filter(p=>p.categoryId!==req.params.id);writeDB(d);res.json({ok:true})});
app.post('/api/admin/products',requireAdmin,(req,res)=>{const b=req.body||{},d=readDB();if(!d.categories.some(c=>c.id===b.categoryId))return res.status(400).json({error:'دسته‌بندی معتبر انتخاب کن.'});const title=String(b.title||'').trim(),price=Number(b.price),stock=Number(b.stock);if(!title||!Number.isFinite(price)||price<0||!Number.isInteger(stock)||stock<0)return res.status(400).json({error:'نام، قیمت و موجودی رو درست وارد کن.'});const p={id:crypto.randomUUID(),categoryId:b.categoryId,title:title.slice(0,100),description:String(b.description||'').slice(0,500),price,stock,image:String(b.image||'').slice(0,500)};d.products.push(p);writeDB(d);res.json(p)});
app.put('/api/admin/products/:id',requireAdmin,(req,res)=>{const d=readDB(),p=d.products.find(x=>x.id===req.params.id);if(!p)return res.status(404).json({error:'محصول پیدا نشد.'});const b=req.body||{};if(b.title!==undefined)p.title=String(b.title).trim().slice(0,100);if(b.description!==undefined)p.description=String(b.description).slice(0,500);if(b.price!==undefined){const n=Number(b.price);if(!Number.isFinite(n)||n<0)return res.status(400).json({error:'قیمت معتبر نیست.'});p.price=n}if(b.stock!==undefined){const n=Number(b.stock);if(!Number.isInteger(n)||n<0)return res.status(400).json({error:'موجودی معتبر نیست.'});p.stock=n}if(b.image!==undefined)p.image=String(b.image).slice(0,500);writeDB(d);res.json(p)});
app.delete('/api/admin/products/:id',requireAdmin,(req,res)=>{const d=readDB();d.products=d.products.filter(p=>p.id!==req.params.id);writeDB(d);res.json({ok:true})});
const storage=multer.diskStorage({destination:(req,file,cb)=>cb(null,UPLOAD_DIR),filename:(req,file,cb)=>cb(null,crypto.randomBytes(16).toString('hex')+path.extname(file.originalname).toLowerCase())});
const upload=multer({storage,limits:{fileSize:5*1024*1024},fileFilter:(req,file,cb)=>cb(null,/^image\/(png|jpeg|webp)$/.test(file.mimetype))});
app.post('/api/admin/upload',requireAdmin,upload.single('image'),(req,res)=>{if(!req.file)return res.status(400).json({error:'فایل تصویر معتبر انتخاب کن.'});res.json({url:'/uploads/'+req.file.filename})});
async function sendTelegramReceipt(message){const token=process.env.TELEGRAM_BOT_TOKEN,adminChat=process.env.TELEGRAM_ADMIN_CHAT_ID;if(!token||!adminChat)return;const endpoint=`https://api.telegram.org/bot${token}/copyMessage`;const body={chat_id:adminChat,from_chat_id:message.chat.id,message_id:message.message_id};try{await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})}catch(e){console.error('Telegram forward failed:',e.message)}}
let polling=false,offset=0;
async function pollBot(){if(polling||!process.env.TELEGRAM_BOT_TOKEN||!process.env.TELEGRAM_ADMIN_CHAT_ID)return;polling=true;try{const r=await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/getUpdates?timeout=20&offset=${offset}`);const j=await r.json();if(j.ok){for(const m of j.result||[]){offset=m.update_id+1;if(m.message&&m.message.chat&&m.message.chat.type==='private'){await sendTelegramReceipt(m.message);if(m.message.chat.id!==Number(process.env.TELEGRAM_ADMIN_CHAT_ID)){await fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id:m.message.chat.id,text:'رسالت و رسیدت برای مدیر فروشگاه ارسال شد.'})}).catch(()=>{})}}}}}catch(e){console.error('Telegram polling:',e.message)}finally{polling=false;setTimeout(pollBot,2500)}}
app.post('/api/orders',async(req,res)=>{const b=req.body||{},name=String(b.name||'').trim(),telegram=String(b.telegram||'').trim();if(!name)return res.status(400).json({error:'نام خریدار الزامی است.'});if(!Array.isArray(b.items)||!b.items.length||b.items.length>60)return res.status(400).json({error:'سبد خرید معتبر نیست.'});const d=readDB(),items=[];let total=0;for(const x of b.items){const p=d.products.find(p=>p.id===x.productId),qty=Number(x.qty);if(!p||!Number.isInteger(qty)||qty<1||qty>100||p.stock<qty)return res.status(400).json({error:'یکی از محصولات ناموجود شده یا موجودی کافی ندارد؛ سبد خرید رو تازه‌سازی کن.'});items.push({productId:p.id,title:p.title,price:p.price,qty});total+=p.price*qty}const order={id:crypto.randomUUID(),name:name.slice(0,80),telegram:telegram.slice(0,80),items,total,createdAt:new Date().toISOString(),status:'pending'};d.orders.unshift(order);writeDB(d);const s=d.settings;res.json({ok:true,total,payment:{cardNumber:s.cardNumber,cardOwner:s.cardOwner,bankName:s.bankName,botUsername:s.botUsername||'ALBERIA3BOT'}})});
const port=Number(process.env.PORT||3000);app.listen(port,'0.0.0.0',()=>{console.log(`ALBERIA SHOP running at http://localhost:${port}`)});
