module.exports = function(mongoose) {
	// Debate topic Schema 
var debateSchema = mongoose.Schema({
  name: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  for_against: { type: Boolean , required: true, unique: false },
  createdate: {type: Date, default: Date.now,  required: true},
  author: { type: String, required: true, unique: true },
  githuballow (type:Boolean, required: true, default:true),
  replies: [commentSchema]
});
}

var commentSchema = mongoose.Schema({


});
}