const {Router} = require('express')
const User = require('../models/User')
const router = Router()
const bcrypt = require('bcryptjs')
const {check, validationResult} = require('express-validator')
const jwt = require("jsonwebtoken")
const config = require("config")
// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Incorrect email').isEmail(),
    check('password', 'Bad password, less than 6 symbols').isLength({min:6})
  ],
   async (req, res) => {
  try{
    const errors = validationResult(req)
    if (!errors.isEmpty()){
      return res.status(400).json({
        errors: errors.array(),
        message: 'Incorrect registration data'
      })
    }
    const {email, password} = req.body
    const candidate = await User.findOne({ email })
    if (candidate){
      return res.status(400).json({message: 'User exist'})
    }
    const hashedPassword = await bcrypt.hash(password, 12)
    const user = new User({ email, password: hashedPassword})
    await user.save()
    res.status(201).json({message: 'User create'})
  }catch(e){
    res.status(500).json({message:'Something wrong'})
  }
})

// /api/auth/login
router.post(
  '/login', 
  [
    check('email', 'Type correct email').normalizeEmail().isEmail(),
    check('password', 'Type password').exists()
  ],
  async (req, res) => {
    try{
      const errors = validationResult(req)
      if (!errors.isEmpty()){
        return res.status(400).json({
          errors: errors.array(),
          message: 'Incorrect data'
        })
      }
      const { email, password } = req.body
      const user = await User.findOne({ email})
      if(!user){
        return res.status(400).json({message: "User Not Found"})
      }
      const isMatch = await bcrypt.compare(password, user.password)
      if(!isMatch){
        return res.status(400).json({ message: 'Incorrect password'})
      }
      const token = jwt.sign(
        { userId: user.id },
        config.get("jwtSecret"),
        { expiresIn: '1h' }
      )
      res.json({ token, userId: user.id})
    }catch(e){
      res.status(500).json({message:'Something wrong'})
    }
})

module.exports = router