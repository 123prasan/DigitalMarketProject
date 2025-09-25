const mongoose=require('mongoose')
const couponSchema = new mongoose.Schema({
  userId:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true},
  code: String,
  file: { type: mongoose.Schema.Types.ObjectId, ref: "File" },
  discountValue: Number,
  expiry: Date
});
module.exports=mongoose.model('Coupon', couponSchema);

