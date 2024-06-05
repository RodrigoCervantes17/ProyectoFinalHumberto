const jwt = require('jsonwebtoken');

module.exports = {
  validateRegister: (req, res, next) => {
    // username min length 3
    if (!req.body.username || req.body.username.length < 3) {
      return res.status(400).send({
        message: 'Username must be longer than 3 characters',
      });
    }
    // password min 6 chars
    if (!req.body.password || req.body.password.length < 6) {
      return res.status(400).send({
        message: 'password must be longer than 6 characters',
      });
    }
    // password (repeat) must match
    if (
      !req.body.password_repeat ||
      req.body.password != req.body.password_repeat
    ) {
      return res.status(400).send({
        message: 'Passwords must match',
      });
    }
    next();
  },
  isLoggedIn: (req, res, next) => {
    if (!req.headers.authorization) {
      return res.status(400).send({
        message: 'Invalid Session',
      });
    }
    try {
      const authHeader = req.headers.authorization;
      const token = authHeader.split(' ')[1];
      const decoded = jwt.verify(token, process.env.SECRET_KEY);
      req.userData = decoded;
      next();
    } catch (err) {
      return res.status(400).send({
        message: 'Invalid session',
      });
    }
  },

admin:(req,res,next) =>{

  if (!req.headers.authorization) {
    return res.status(400).send({
      message: 'Invalid Session',
    });
  }
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.SECRET_KEY);
    req.userData = decoded;
    
    if (decoded.admin == 1) {
        next();
    }
  }
  
   catch (err) {
  return res.status(400).send({
    message: 'Invalid session',
  });
}}
};
