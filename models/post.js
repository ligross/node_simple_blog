var mongoose    = require('mongoose');

var Schema      = mongoose.Schema;

var PostSchema   = new Schema({
    user_id:    String,
    title:      String,
    body:       String,
    created_at: { type: Date,    default: Date.now }
});

module.exports = mongoose.model('Post', PostSchema);
