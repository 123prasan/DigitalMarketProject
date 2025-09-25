const mongoose=require("mongoose")
const log_activiesSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    last_logged_in: [{ date: { type: Date, default: Date.now } }],
    last_logged_out: [{ date: { type: Date } }],
});
const log_activities = mongoose.model('LogActivities', log_activiesSchema);
module.exports=log_activities;