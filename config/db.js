const { connect } = require('mongoose');

const mongoDBConnect = async () => {
  try {
    connect(process.env.MONGO_STRING);
    console.log(`MongoDB Database is connected`.bgGreen);
  } catch (error) {
    console.log(error);
  }
};

module.exports = mongoDBConnect;
