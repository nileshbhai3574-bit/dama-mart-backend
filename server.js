require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const Razorpay = require("razorpay");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://damamart.netlify.app";
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.ADMIN_USER || "admin@damamart.com";
const ADMIN_PASS = process.env.ADMIN_PASS || "";
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH || "";
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID;
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) throw new Error("JWT_SECRET is required");
if (!DATABASE_URL) throw new Error("DATABASE_URL is required. Create a Render PostgreSQL database and add its Internal Database URL.");

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false });
const razorpay = RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET ? new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET }) : null;

const PRODUCTS = new Map([
  [1,{name:"Rice",emoji:"🍚",weight:"5 kg",price:320}], [2,{name:"Wheat Atta",emoji:"🌾",weight:"5 kg",price:280}],
  [3,{name:"Toor Dal",emoji:"🫘",weight:"1 kg",price:150}], [4,{name:"Sugar",emoji:"🍬",weight:"1 kg",price:48}],
  [5,{name:"Cooking Oil",emoji:"🫗",weight:"1 L",price:145}], [6,{name:"Salt",emoji:"🧂",weight:"1 kg",price:25}],
  [7,{name:"Tea",emoji:"🍵",weight:"250 g",price:120}], [8,{name:"Biscuits",emoji:"🍪",weight:"120 g",price:25}],
  [9,{name:"Dishwash Liquid",emoji:"🧴",weight:"500 ml",price:95}], [10,{name:"Floor Cleaner",emoji:"🧹",weight:"1 L",price:120}],
  [11,{name:"Garbage Bags",emoji:"🗑️",weight:"30 pcs",price:80}], [12,{name:"Storage Container",emoji:"🫙",weight:"1 pc",price:150}],
  [13,{name:"Notebook",emoji:"📓",weight:"1 pc",price:55}], [14,{name:"Ball Pen",emoji:"🖊️",weight:"5 pcs",price:40}],
  [15,{name:"Pencil",emoji:"✏️",weight:"10 pcs",price:35}], [16,{name:"Eraser",emoji:"◻️",weight:"5 pcs",price:20}],
  [17,{name:"School Bag",emoji:"🎒",weight:"1 pc",price:450}], [18,{name:"A4 Paper",emoji:"📄",weight:"100 sheets",price:90}],
  [19,{name:"Practical File",emoji:"📁",weight:"1 pc",price:65}], [20,{name:"Geometry Box",emoji:"📐",weight:"1 pc",price:120}]
]);

app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: FRONTEND_ORIGIN, credentials: true, methods: ["GET","POST","PATCH","OPTIONS"], allowedHeaders: ["Content-Type","X-CSRF-Token"] }));
app.use(cookieParser());
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: false, limit: "50kb" }));

const generalLimiter = rateLimit({ windowMs: 15*60*1000, limit: 300, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 10, standardHeaders: true, legacyHeaders: false, message: {message:"Too many login attempts. Please try again later."} });
const paymentLimiter = rateLimit({ windowMs: 5*60*1000, limit: 20, standardHeaders: true, legacyHeaders: false });
app.use("/api/", generalLimiter);

function csrfCookieOptions(){ return { httpOnly:false, secure:true, sameSite:"none", maxAge: 2*60*60*1000, path:"/" }; }
function sessionCookieOptions(){ return { httpOnly:true, secure:true, sameSite:"none", maxAge: 2*60*60*1000, path:"/" }; }
function issueSession(res, user){
  const csrf = crypto.randomBytes(24).toString("hex");
  const token = jwt.sign({sub:String(user.id), role:user.role, email:user.email, csrf}, JWT_SECRET, {expiresIn:"2h", issuer:"dama-mart"});
  return {token,csrf};
}
function clearSession(res){ res.clearCookie("dm_session", {httpOnly:true, secure:true, sameSite:"none", path:"/"}); res.clearCookie("dm_csrf", {secure:true, sameSite:"none", path:"/"}); }
function getSession(req){
  const h=req.get("Authorization")||""; const token=h.startsWith("Bearer ")?h.slice(7):null;
  if(!token) return null;
  try{return jwt.verify(token, JWT_SECRET, {issuer:"dama-mart"});}catch{return null;}
}
function requireAuth(req,res,next){
  const s=getSession(req); if(!s) return res.status(401).json({message:"Login required"});
  req.user=s; next();
}
function requireAdmin(req,res,next){ if(req.user?.role!=="admin") return res.status(403).json({message:"Admin access required"}); next(); }
function sanitizeText(v,max=500){return String(v??"").trim().slice(0,max);}
function validPhone(v){return /^[0-9+()\-\s]{8,20}$/.test(v);}
function normalizeItems(input){
  if(!Array.isArray(input)||!input.length||input.length>50) throw new Error("Invalid items");
  const items=input.map(x=>{const id=Number(x.id), qty=Number(x.qty); const p=PRODUCTS.get(id); if(!p||!Number.isInteger(qty)||qty<1||qty>99) throw new Error("Invalid product or quantity"); return {id,name:p.name,emoji:p.emoji,weight:p.weight,price:p.price,qty,amount:p.price*qty};});
  const subtotal=items.reduce((s,x)=>s+x.amount,0); const delivery=subtotal<200?10:0; return {items,subtotal,delivery,total:subtotal+delivery};
}
async function initDb(){
  await pool.query(`CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,phone TEXT NOT NULL,address TEXT NOT NULL,password_hash TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
  CREATE TABLE IF NOT EXISTS orders(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),items JSONB NOT NULL,subtotal INTEGER NOT NULL,delivery INTEGER NOT NULL,total INTEGER NOT NULL,payment_method TEXT NOT NULL,payment_status TEXT NOT NULL,status TEXT NOT NULL,razorpay_order_id TEXT,razorpay_payment_id TEXT,delivery_boy JSONB,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
  CREATE INDEX IF NOT EXISTS idx_orders_user_created ON orders(user_id,created_at DESC); CREATE INDEX IF NOT EXISTS idx_orders_razorpay ON orders(razorpay_order_id);
  CREATE TABLE IF NOT EXISTS audit_logs(id BIGSERIAL PRIMARY KEY,actor_role TEXT,actor_id TEXT,action TEXT,order_id TEXT,ip TEXT,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
}
async function audit(req,action,orderId=null){try{await pool.query("INSERT INTO audit_logs(actor_role,actor_id,action,order_id,ip) VALUES($1,$2,$3,$4,$5)",[req.user?.role||"system",req.user?.sub||"system",action,orderId,req.ip]);}catch(e){console.error("audit",e.message)}}

app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({ok:true,service:"Dama Mart",database:true,security:"enabled"});}catch{res.status(503).json({ok:false,service:"Dama Mart",database:false});}});
app.get("/api/auth/csrf",(req,res)=>res.json({ok:false,message:"Bearer session authentication is used"}));

app.post("/api/auth/signup",authLimiter,async(req,res)=>{
  try{const name=sanitizeText(req.body?.name,100),email=sanitizeText(req.body?.email,150).toLowerCase(),password=String(req.body?.password||""),phone=sanitizeText(req.body?.phone,20),address=sanitizeText(req.body?.address,500);
    if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||password.length<8||!validPhone(phone)||address.length<5) return res.status(400).json({message:"Enter valid name, email, password (8+ chars), mobile and address."});
    const hash=await bcrypt.hash(password,12), id=crypto.randomUUID();
    await pool.query("INSERT INTO users(id,email,name,phone,address,password_hash) VALUES($1,$2,$3,$4,$5,$6)",[id,email,name,phone,address,hash]);
    const user={id,email,name,phone,address,role:"customer"}; const session=issueSession(res,user); res.status(201).json({ok:true,user,token:session.token});
  }catch(e){if(e.code==="23505") return res.status(409).json({message:"Account already exists. Please login."}); console.error(e);res.status(500).json({message:"Account creation failed"});}
});
app.post("/api/auth/login",authLimiter,async(req,res)=>{
  try{const email=sanitizeText(req.body?.email,150).toLowerCase(),password=String(req.body?.password||""); const r=await pool.query("SELECT * FROM users WHERE email=$1",[email]); const u=r.rows[0]; if(!u||!(await bcrypt.compare(password,u.password_hash))) return res.status(401).json({message:"Invalid email or password"});
    const user={id:u.id,email:u.email,name:u.name,phone:u.phone,address:u.address,role:"customer"}; const session=issueSession(res,user); await audit({user:{role:"customer",sub:u.id},ip:req.ip},"customer_login"); res.json({ok:true,user,token:session.token});
  }catch(e){res.status(500).json({message:"Login failed"});}
});
app.post("/api/auth/logout",requireAuth,(req,res)=>res.json({ok:true}));
app.get("/api/auth/me",requireAuth,async(req,res)=>{
  if(req.user.role==="admin") return res.json({ok:true,user:{email:req.user.email,role:"admin"}});
  const r=await pool.query("SELECT id,email,name,phone,address FROM users WHERE id=$1",[req.user.sub]); if(!r.rows[0]) return res.status(401).json({message:"Account not found"}); res.json({ok:true,user:{...r.rows[0],role:"customer"}});
});

app.post("/api/admin/login",authLimiter,async(req,res)=>{
  const username=sanitizeText(req.body?.username,150).toLowerCase(), password=String(req.body?.password||"");
  const validUser=username===ADMIN_USER.toLowerCase(); let validPass=false;
  if(ADMIN_PASSWORD_HASH) validPass=await bcrypt.compare(password,ADMIN_PASSWORD_HASH); else if(ADMIN_PASS){ const a=Buffer.from(password), b=Buffer.from(ADMIN_PASS); validPass=a.length===b.length && crypto.timingSafeEqual(a,b); }
  if(!validUser||!validPass) return res.status(401).json({message:"Invalid admin credentials"});
  const session=issueSession(res,{id:"admin",email:ADMIN_USER,role:"admin"}); await audit({user:{role:"admin",sub:"admin"},ip:req.ip},"admin_login"); res.json({ok:true,user:{email:ADMIN_USER,role:"admin"},token:session.token});
});

app.post("/api/payment/create-order",paymentLimiter,requireAuth,async(req,res)=>{
  try{if(req.user.role!=="customer") return res.status(403).json({message:"Customer account required"}); if(!razorpay) return res.status(500).json({message:"Razorpay keys are not configured"});
    const calc=normalizeItems(req.body?.items); const user=(await pool.query("SELECT id,email,name,phone,address FROM users WHERE id=$1",[req.user.sub])).rows[0]; if(!user) return res.status(401).json({message:"Account not found"});
    const id="DM"+Date.now().toString().slice(-8)+crypto.randomInt(10,99); const rp=await razorpay.orders.create({amount:calc.total*100,currency:"INR",receipt:id,payment_capture:1});
    await pool.query("INSERT INTO orders(id,user_id,items,subtotal,delivery,total,payment_method,payment_status,status,razorpay_order_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",[id,user.id,JSON.stringify(calc.items),calc.subtotal,calc.delivery,calc.total,"Razorpay","Created","Payment Pending",rp.id]);
    await audit(req,"razorpay_order_created",id); res.json({key_id:RAZORPAY_KEY_ID,order:rp,internal_order_id:id,customer:user,totals:calc});
  }catch(e){console.error("create-order",e);res.status(400).json({message:e.message||"Unable to create payment order"});}
});

app.post("/api/payment/verify",paymentLimiter,requireAuth,async(req,res)=>{
  try{if(req.user.role!=="customer"||!razorpay) return res.status(403).json({verified:false,message:"Invalid payment request"}); const {razorpay_order_id,razorpay_payment_id,razorpay_signature,internal_order_id}=req.body||{}; if(!razorpay_order_id||!razorpay_payment_id||!razorpay_signature||!internal_order_id) return res.status(400).json({verified:false,message:"Missing payment fields"});
    const ord=(await pool.query("SELECT * FROM orders WHERE id=$1 AND user_id=$2",[internal_order_id,req.user.sub])).rows[0]; if(!ord||ord.razorpay_order_id!==razorpay_order_id) return res.status(404).json({verified:false,message:"Order not found"});
    const expected=crypto.createHmac("sha256",RAZORPAY_KEY_SECRET).update(razorpay_order_id+"|"+razorpay_payment_id).digest("hex"); const a=Buffer.from(expected),b=Buffer.from(String(razorpay_signature)); if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return res.status(400).json({verified:false,message:"Invalid payment signature"});
    const payment=await razorpay.payments.fetch(razorpay_payment_id); if(payment.order_id!==razorpay_order_id||Number(payment.amount)!==Number(ord.total)*100||payment.status!=="captured") return res.status(400).json({verified:false,message:"Payment verification failed"});
    await pool.query("UPDATE orders SET payment_status='Paid - Razorpay verified',status='Order Placed',razorpay_payment_id=$1,updated_at=NOW() WHERE id=$2",[payment.id,ord.id]); await audit(req,"payment_verified",ord.id); res.json({verified:true,order_id:ord.id,payment_id:payment.id,status:"captured",amount:ord.total});
  }catch(e){console.error("verify",e);res.status(400).json({verified:false,message:"Payment verification failed"});}
});

app.post("/api/payment/failed",paymentLimiter,requireAuth,async(req,res)=>{try{const id=sanitizeText(req.body?.internal_order_id,40),reason=sanitizeText(req.body?.reason,300); const r=await pool.query("UPDATE orders SET payment_status='Payment Failed',status='Payment Failed',updated_at=NOW() WHERE id=$1 AND user_id=$2 RETURNING id,status,payment_status",[id,req.user.sub]); if(!r.rows[0]) return res.status(404).json({message:"Order not found"}); await audit(req,"payment_failed:"+reason,id);res.json({ok:true,order:r.rows[0]});}catch(e){res.status(400).json({message:"Could not update payment failure"});}});

app.post("/api/orders",requireAuth,async(req,res)=>{
  try{if(req.user.role!=="customer") return res.status(403).json({message:"Customer account required"}); const calc=normalizeItems(req.body?.items); const method=req.body?.paymentMethod; if(method!=="Cash on Delivery") return res.status(400).json({message:"Online orders must use Razorpay verification"}); const id="DM"+Date.now().toString().slice(-8)+crypto.randomInt(10,99); await pool.query("INSERT INTO orders(id,user_id,items,subtotal,delivery,total,payment_method,payment_status,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",[id,req.user.sub,JSON.stringify(calc.items),calc.subtotal,calc.delivery,calc.total,"Cash on Delivery","COD - PAYMENT DUE ON DELIVERY","Order Placed"]); const o=(await getOrder(id,req.user)).rows[0]; await audit(req,"cod_order_created",id);res.status(201).json(publicOrder(o));}catch(e){res.status(400).json({message:e.message||"Invalid order"});}
});
async function getOrder(id,user){if(user.role==="admin") return pool.query("SELECT o.*,u.email,u.name,u.phone,u.address FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=$1",[id]); return pool.query("SELECT o.*,u.email,u.name,u.phone,u.address FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=$1 AND o.user_id=$2",[id,user.sub]);}
function publicOrder(o){if(!o)return null;return {id:o.id,createdAt:o.created_at,updatedAt:o.updated_at,customer:{name:o.name,phone:o.phone,address:o.address,username:o.email},items:o.items,subtotal:o.subtotal,delivery:o.delivery,total:o.total,paymentMethod:o.payment_method,paymentStatus:o.payment_status,status:o.status,deliveryBoy:o.delivery_boy,razorpayOrderId:o.razorpay_order_id||undefined};}
app.get("/api/orders",requireAuth,async(req,res)=>{const q=req.user.role==="admin"?await pool.query("SELECT o.*,u.email,u.name,u.phone,u.address FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.created_at DESC LIMIT 500"):await pool.query("SELECT o.*,u.email,u.name,u.phone,u.address FROM orders o JOIN users u ON u.id=o.user_id WHERE o.user_id=$1 ORDER BY o.created_at DESC",[req.user.sub]);res.json(q.rows.map(publicOrder));});
app.get("/api/orders/:id",requireAuth,async(req,res)=>{const q=await getOrder(req.params.id,req.user);if(!q.rows[0])return res.status(404).json({message:"Order not found"});res.json(publicOrder(q.rows[0]));});
app.patch("/api/orders/:id/status",requireAuth,requireAdmin,async(req,res)=>{const allowed=["Order Placed","Accepted","Preparing","Out for Delivery","Delivered","Payment Failed"];const status=sanitizeText(req.body?.status,40);if(!allowed.includes(status))return res.status(400).json({message:"Invalid status"});const q=await pool.query("UPDATE orders SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING *",[status,req.params.id]);if(!q.rows[0])return res.status(404).json({message:"Order not found"});await audit(req,"status:"+status,req.params.id);const o=(await getOrder(req.params.id,req.user)).rows[0];res.json(publicOrder(o));});
app.patch("/api/orders/:id/delivery",requireAuth,requireAdmin,async(req,res)=>{const name=sanitizeText(req.body?.name,100),phone=sanitizeText(req.body?.phone,20);if(name.length<2||!validPhone(phone))return res.status(400).json({message:"Invalid delivery details"});const q=await pool.query("UPDATE orders SET delivery_boy=$1,updated_at=NOW() WHERE id=$2 RETURNING *",[JSON.stringify({name,phone}),req.params.id]);if(!q.rows[0])return res.status(404).json({message:"Order not found"});await audit(req,"delivery_assigned",req.params.id);const o=(await getOrder(req.params.id,req.user)).rows[0];res.json(publicOrder(o));});

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({message:"Server error"});});
initDb().then(()=>app.listen(PORT,()=>console.log(`Dama Mart secure server running on ${PORT}`))).catch(e=>{console.error("Database init failed",e);process.exit(1)});
