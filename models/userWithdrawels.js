const mongoose=require("mongoose");
const WithDraw=new mongoose.Schema({
    totalAmount:{type:Number,required:true,min:100},
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true},
    status:{type:String,default:"pending",enum:["pending","success","failed"]},
    transactionId:{type:String,required:true},
    createdAt:{type:Date,default:Date.now}
})
module.exports=mongoose.model("WithDraw",WithDraw);