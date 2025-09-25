const mongoose=require("mongoose");
const withDrawelReqs=new mongoose.Schema({
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true},
    Amount:{type:Number,required:true},
    paymentway:{type:String,required:true},
    status:{type:String,default:"pending",enum:["pending","success","failed"]},
    createAt:{type:Date,default:Date.now}

})
module.exports=mongoose.model("withDrawelReqs",withDrawelReqs);