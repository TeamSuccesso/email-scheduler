const mongoose = require("mongoose");

const emailSchema = new mongoose.Schema({
  id:        { type: String, required: true, unique: true },
  userEmail: { type: String, default: '' },

  to:  { type: String, default: '' },
  cc:  { type: String, default: '' },
  bcc: { type: String, default: '' },

  subject:  { type: String, default: '' },
  body:     { type: String, default: '' },
  bodyType: { type: String, default: 'text' },

  attachments:   { type: Array,  default: [] },
  attachmentIds: { type: Array,  default: [] },

  recurrence: { type: Object, default: {} },
  type:       { type: String, default: 'once' },
  time:       { type: String, default: '08:00' },

  nextSendTime: { type: String, default: null },
  lastSent:     { type: String, default: null },
  inFlightUntil:{ type: String, default: null },

  sentCount: { type: Number,  default: 0 },
  maxTimes:  { type: String,  default: 'indefinitely' },

  active:    { type: Boolean, default: true },
  createdAt: { type: String,  default: () => new Date().toISOString() },
});

module.exports = mongoose.model("Email", emailSchema);
