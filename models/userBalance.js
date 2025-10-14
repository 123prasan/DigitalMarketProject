const mongoose=require("mongoose");
const UserBal=new mongoose.Schema({
    UserId:{type:String,required:true,unique:true},
    Balance:{type:Number,default:0},
    prevBal:{type:Number,default:0},

},{timestamps:true})
module.exports = mongoose.models.UserBal || mongoose.model("UserBal", UserBal);