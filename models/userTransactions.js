const mongoose=require("mongoose");
const userTran=new mongoose.Schema({
    ProductName:{type:String,required:true},
    ProductId:{type:String,required:true},
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true},
    status:{type:String,required:true,default:"Completed"},
    totalAmount:{type:Number,required:true},
    discount:{type:Number,default:0},
    transactionId:{type:String,required:true},
    purchaserId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true}
},{ timestamps: true });
module.exports=mongoose.model("UserTransaction",userTran);