const mongoose=require("mongoose");
const AdminBal=new mongoose.Schema({
  totalAmount:{type:Number,required:true,default:0},
  cutOffbal:{type:Number,required:true,default:0},

})
module.exports=mongoose.model("AdminBal",AdminBal);