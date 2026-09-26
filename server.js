require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("."));

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || "admin@damamart.com";
const ADMIN_PASS = process.env.ADMIN_PASS || "DamaAdmin@2026";

let orders = [];

app.get("/api/health", (req,res)=>res.json({ok:true,service:"Dama Mart"}));

app.post("/api/admin/login",(req,res)=>{
  const {username,password}=req.body||{};
  if(username===ADMIN_USER && password===ADMIN_PASS)
    return res.json({ok:true,token:crypto.randomBytes(24).toString("hex")});
  res.status(401).json({ok:false,message:"Invalid admin credentials"});
});

app.get("/api/orders",(req,res)=>res.json(orders));

app.get("/api/orders/:id",(req,res)=>{
  const o=orders.find(x=>x.id===req.params.id);
  if(!o)return res.status(404).json({message:"Order not found"});
  res.json(o);
});

app.post("/api/orders",(req,res)=>{
  const o=req.body;
  if(!o || !o.customer || !o.items) return res.status(400).json({message:"Invalid order"});
  const id=o.id || "DM"+Date.now().toString().slice(-8);
  const order={...o,id,status:o.status||"Order Placed",createdAt:o.createdAt||new Date().toISOString()};
  orders.unshift(order);
  res.status(201).json(order);
});

app.patch("/api/orders/:id/status",(req,res)=>{
  const o=orders.find(x=>x.id===req.params.id);
  if(!o)return res.status(404).json({message:"Order not found"});
  const allowed=["Order Placed","Accepted","Preparing","Out for Delivery","Delivered"];
  if(!allowed.includes(req.body.status))return res.status(400).json({message:"Invalid status"});
  o.status=req.body.status;o.updatedAt=new Date().toISOString();
  res.json(o);
});

app.patch("/api/orders/:id/delivery",(req,res)=>{
  const o=orders.find(x=>x.id===req.params.id);
  if(!o)return res.status(404).json({message:"Order not found"});
  o.deliveryBoy=req.body;res.json(o);
});

app.listen(PORT,()=>console.log(`Dama Mart server running on http://localhost:${PORT}`));
