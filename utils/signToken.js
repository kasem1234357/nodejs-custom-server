const jwt = require('jsonwebtoken')
/**
 * Description
 * @param {string} id
 * @param {('access'|'refresh')} type='access'
 * @returns {string}
 * 
 * return encrypted Token by jsonWebToken
 */
const signToken = (id,type='access')=>{
    if(type ==='access'){
        return jwt.sign({id},process.env.ACCESS_TOKEN_SECRET,{
            expiresIn:eval(process.env.EXPIRE_ACCESS_TOKEN)
            
        })
    }
    else{
        return jwt.sign({id},process.env.REFRESH_TOKEN_SECRET)  
    }
    
}
module.exports = signToken
// 