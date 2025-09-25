const mongoose=require("mongoose");
const Account=new mongoose.Schema({
   userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
   TotalBal:{type:Number,required:true,default:0},
   PrevBal:{type:Number,required:true,default:0},
   ToalWithDraw:{type:Number,required:true,default:0},
})