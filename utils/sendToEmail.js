const nodemailer = require('nodemailer')
const handleError = require('./errorHandeler')
const dotenv = require("dotenv");
dotenv.config();

/**
 * Description
 * @param {object} options
 * @returns {Promise}
 */
const sendToEmail= async(options)=>{
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port:process.env.EMAIL_PORT,
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASSWORD,
        },
      });
      let isSuccess = true
      // Setup email data
      const mailOptions = {
        from: 'midnightX.app',
        to: options.email,
        subject: options.subject,
        text: options.message,
      };
      // Send the email
       await transporter.sendMail(mailOptions).then(res =>{
        isSuccess = true
      }).catch(err =>{
        isSuccess = false
      });
      return isSuccess
}  
module.exports = sendToEmail