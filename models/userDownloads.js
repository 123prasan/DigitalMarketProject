const { text } = require("body-parser");
const mongoose=require("mongoose");
const userdownloads=new mongoose.Schema({
    userId:{type:mongoose.Schema.Types.ObjectId,ref:"User",required:true},
    filename:{type:String,required:true},
    fileId:{type:mongoose.Schema.Types.ObjectId,ref:"File",required:true},
    fileUrl:{type:String,required:true},
    fileType:{type:String,required:true}
},{timestamps:true});
module.exports=mongoose.model("userdownloads",userdownloads)
