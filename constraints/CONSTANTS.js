 const REPORT_STATES = {
    NOT_READ: 1,
    IN_PROGRESS: 2,
    FIXED: 3,
  };
const GET_VERIFIED_EMAIL_MASSEGE = (code)=>{
   return `the code for verfication is \n ${code}`
}
 const SET_VERIFIED_EMAIL_MASSEGE =()=>{
  return `you are verified now `
}
const GET_RESET_PASSWORD_URL = (url)=>{
  return `this is reset password url ${url}
  its valid for 15 min`
}
module.exports = {
  REPORT_STATES,
  GET_VERIFIED_EMAIL_MASSEGE,
  SET_VERIFIED_EMAIL_MASSEGE,
  GET_RESET_PASSWORD_URL
}